// File-based IPC between short-lived hook processes and the long-lived approval TUI.
// A blocked hook writes `<id>.req.json` into the queue dir and polls for the matching
// `<id>.verdict.json` the TUI writes back. A heartbeat file signals the TUI is alive;
// when it is stale the hook never blocks and falls back to Claude Code's own prompt.

use crate::config::{expand_tilde, ApprovalConfig};
use crate::decision::Decision;
use crate::log::now_ms;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_STATE_DIR: &str = "~/.local/state/lord-kali";

#[derive(Serialize, Deserialize)]
pub(crate) struct QueueRequest {
    pub(crate) id: String,
    pub(crate) ts_ms: u64,
    pub(crate) cwd: Option<String>,
    pub(crate) tool: String,
    pub(crate) target: String,
    pub(crate) nodes: Vec<QueueNode>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct QueueNode {
    pub(crate) shell: String,
    pub(crate) command: String,
    pub(crate) args: String,
    // "ask" or "passthrough" — why this node is actionable.
    pub(crate) decision: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Verdict {
    pub(crate) id: String,
    pub(crate) nodes: Vec<VerdictNode>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct VerdictNode {
    pub(crate) command: String,
    pub(crate) args: String,
    pub(crate) action: Action,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    AllowOnce,
    AllowAlways,
    DenyOnce,
    DenyAlways,
    Passthrough,
}

// Resolve the per-node operator actions into one verdict for the whole tool call:
// any deny -> deny; else any node left as passthrough -> defer to Claude Code (None);
// else (all allowed, non-empty) -> allow.
pub(crate) fn combine_verdict(nodes: &[VerdictNode]) -> Option<(Decision, String)> {
    let denied: Vec<&str> = nodes
        .iter()
        .filter(|n| matches!(n.action, Action::DenyOnce | Action::DenyAlways))
        .map(|n| n.command.as_str())
        .collect();
    if !denied.is_empty() {
        return Some((
            Decision::Deny,
            format!("Denied at approval TUI: {}", denied.join(", ")),
        ));
    }
    if nodes.iter().any(|n| n.action == Action::Passthrough) || nodes.is_empty() {
        return None;
    }
    Some((Decision::Allow, "Approved at approval TUI".into()))
}

pub(crate) fn state_dir(approval: &ApprovalConfig) -> PathBuf {
    expand_tilde(approval.state_dir.as_deref().unwrap_or(DEFAULT_STATE_DIR))
}

fn heartbeat_in(dir: &Path) -> PathBuf {
    dir.join("tui.heartbeat")
}

pub(crate) fn queue_dir_in(dir: &Path) -> PathBuf {
    dir.join("queue")
}

pub(crate) fn request_id(session_id: &str) -> String {
    format!("{}-{}-{}", session_id, now_ms(), std::process::id())
}

// Write to a sibling temp file then rename, so a reader never observes a partial file.
pub(crate) fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

pub(crate) fn write_heartbeat_in(dir: &Path) -> std::io::Result<()> {
    write_atomic(&heartbeat_in(dir), &now_ms().to_string())
}

pub(crate) fn is_tui_live_in(dir: &Path, heartbeat_fresh_ms: u64) -> bool {
    match std::fs::read_to_string(heartbeat_in(dir)) {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .is_ok_and(|ts| now_ms().saturating_sub(ts) <= heartbeat_fresh_ms),
        Err(_) => false,
    }
}

// Enqueue a request and block until the TUI writes a verdict or the timeout elapses.
// On timeout the request file is removed so the TUI does not keep showing a dead entry.
pub(crate) fn submit_and_wait_in(
    dir: &Path,
    request: &QueueRequest,
    timeout_ms: u64,
    poll_ms: u64,
) -> Option<Verdict> {
    let qdir = queue_dir_in(dir);
    let req_path = qdir.join(format!("{}.req.json", request.id));
    let verdict_path = qdir.join(format!("{}.verdict.json", request.id));

    let json = serde_json::to_string(request).ok()?;
    write_atomic(&req_path, &json).ok()?;

    let deadline = now_ms() + timeout_ms;
    loop {
        if let Ok(s) = std::fs::read_to_string(&verdict_path) {
            if let Ok(v) = serde_json::from_str::<Verdict>(&s) {
                let _ = std::fs::remove_file(&verdict_path);
                let _ = std::fs::remove_file(&req_path);
                return Some(v);
            }
        }
        if now_ms() >= deadline {
            let _ = std::fs::remove_file(&req_path);
            return None;
        }
        std::thread::sleep(Duration::from_millis(poll_ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vnode(command: &str, action: Action) -> VerdictNode {
        VerdictNode {
            command: command.into(),
            args: String::new(),
            action,
        }
    }

    #[test]
    fn combine_all_allow_is_allow() {
        let nodes = vec![
            vnode("gh", Action::AllowOnce),
            vnode("jq", Action::AllowAlways),
        ];
        assert_eq!(
            combine_verdict(&nodes).map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn combine_any_deny_is_deny() {
        let nodes = vec![
            vnode("gh", Action::AllowAlways),
            vnode("curl", Action::DenyOnce),
        ];
        let (d, reason) = combine_verdict(&nodes).unwrap();
        assert_eq!(d, Decision::Deny);
        assert!(reason.contains("curl"));
    }

    #[test]
    fn combine_any_passthrough_is_none() {
        let nodes = vec![
            vnode("gh", Action::AllowAlways),
            vnode("jq", Action::Passthrough),
        ];
        assert_eq!(combine_verdict(&nodes), None);
    }

    #[test]
    fn combine_empty_is_none() {
        assert_eq!(combine_verdict(&[]), None);
    }

    #[test]
    fn request_verdict_round_trip() {
        let req = QueueRequest {
            id: "s1-1-2".into(),
            ts_ms: 7,
            cwd: Some("/x".into()),
            tool: "Bash".into(),
            target: "gh pr list".into(),
            nodes: vec![QueueNode {
                shell: "bash".into(),
                command: "gh".into(),
                args: "pr list".into(),
                decision: "passthrough".into(),
            }],
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: QueueRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back.id, "s1-1-2");
        assert_eq!(back.nodes[0].command, "gh");

        let verdict = Verdict {
            id: "s1-1-2".into(),
            nodes: vec![vnode("gh", Action::AllowAlways)],
        };
        let vs = serde_json::to_string(&verdict).unwrap();
        assert!(vs.contains("allow_always"));
        let vback: Verdict = serde_json::from_str(&vs).unwrap();
        assert_eq!(vback.nodes[0].action, Action::AllowAlways);
    }

    #[test]
    fn write_atomic_leaves_no_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sub/dir/file.json");
        write_atomic(&path, "hello").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
        let mut tmp_name = path.as_os_str().to_owned();
        tmp_name.push(".tmp");
        assert!(!PathBuf::from(tmp_name).exists());
    }

    #[test]
    fn heartbeat_live_then_stale_then_absent() {
        use crate::config::DEFAULT_HEARTBEAT_FRESH_MS as FRESH;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        assert!(!is_tui_live_in(dir, FRESH), "absent heartbeat is not live");

        write_heartbeat_in(dir).unwrap();
        assert!(is_tui_live_in(dir, FRESH), "fresh heartbeat is live");

        // Stamp an old timestamp directly to simulate a dead TUI.
        write_atomic(&heartbeat_in(dir), &(now_ms() - FRESH - 1000).to_string()).unwrap();
        assert!(!is_tui_live_in(dir, FRESH), "stale heartbeat is not live");
    }

    #[test]
    fn submit_returns_verdict_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let req = QueueRequest {
            id: "sess-9-9".into(),
            ts_ms: 0,
            cwd: None,
            tool: "Bash".into(),
            target: "gh".into(),
            nodes: vec![],
        };
        // Pre-place the verdict the TUI would write; first poll should pick it up.
        let verdict = Verdict {
            id: "sess-9-9".into(),
            nodes: vec![vnode("gh", Action::AllowOnce)],
        };
        let vpath = queue_dir_in(dir).join("sess-9-9.verdict.json");
        write_atomic(&vpath, &serde_json::to_string(&verdict).unwrap()).unwrap();

        let got = submit_and_wait_in(dir, &req, 1000, 10).unwrap();
        assert_eq!(got.nodes[0].action, Action::AllowOnce);
        // Both request and verdict files are cleaned up.
        assert!(!vpath.exists());
        assert!(!queue_dir_in(dir).join("sess-9-9.req.json").exists());
    }

    #[test]
    fn submit_times_out_and_cleans_request() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let req = QueueRequest {
            id: "sess-no-verdict".into(),
            ts_ms: 0,
            cwd: None,
            tool: "Bash".into(),
            target: "gh".into(),
            nodes: vec![],
        };
        assert!(submit_and_wait_in(dir, &req, 30, 10).is_none());
        assert!(!queue_dir_in(dir).join("sess-no-verdict.req.json").exists());
    }
}
