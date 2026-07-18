mod config;
mod decision;
mod eval;
mod live_rules;
mod llm;
mod log;
mod parse;
mod queue;
mod scope;
mod watch;
mod worktree;

use config::{load_config, Config};
use decision::{dispatch, Decision, InvocationTrace};
use log::{log_invocation, log_post_tool_use};
use queue::QueueRequest;
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
pub(crate) struct HookInput {
    pub(crate) tool_name: String,
    pub(crate) tool_input: ToolInput,
    pub(crate) cwd: Option<String>,
    #[serde(default)]
    pub(crate) hook_event_name: Option<String>,
    #[serde(default)]
    pub(crate) session_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ToolInput {
    pub(crate) command: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) query: Option<String>,
    pub(crate) file_path: Option<String>,
    pub(crate) path: Option<String>,
    // Any remaining input keys (e.g. an MCP tool's structured arguments), captured for the
    // MCP summary. The typed fields above are pulled out first, so they are NOT here.
    #[serde(flatten)]
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

impl ToolInput {
    // A compact, truncated one-line view of the structured input, shown to the operator on
    // MCP nodes. Display only — MCP gating matches the tool name, never this. The typed
    // fields are folded back in so a tool whose arg is named `url`/`path` still shows it.
    pub(crate) fn summary(&self) -> String {
        let mut obj = self.extra.clone();
        for (k, v) in [
            ("command", &self.command),
            ("url", &self.url),
            ("file_path", &self.file_path),
            ("path", &self.path),
        ] {
            if let Some(val) = v {
                obj.insert(k.into(), serde_json::Value::String(val.clone()));
            }
        }
        let s = serde_json::Value::Object(obj).to_string();
        const MAX: usize = 80;
        if s.chars().count() > MAX {
            format!("{}…", s.chars().take(MAX).collect::<String>())
        } else {
            s
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("watch") => watch::watch(&args.collect::<Vec<_>>()),
        Some("prune-logs") => log::prune_logs_cli(&args.collect::<Vec<_>>()),
        Some("eval") => eval::eval_cli(&args.collect::<Vec<_>>()),
        _ => run_hook(),
    }
}

fn run_hook() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("Failed to read stdin");

    let hook_input: HookInput = serde_json::from_str(&input).expect("Failed to parse hook input");
    let cwd = hook_input.cwd.as_deref();

    let config = load_config(cwd);

    if hook_input.hook_event_name.as_deref() == Some("PostToolUse") {
        if let Some(log) = &config.log {
            if log.enabled {
                log_post_tool_use(log, &input);
            }
        }
        return;
    }

    let trace = dispatch(&config, &hook_input, cwd);
    let trace = maybe_route_to_approval(&config, &hook_input, trace);

    if let Some((decision, reason)) = &trace.final_decision {
        print_decision(decision.clone(), reason);
    }

    if let Some(log) = &config.log {
        if log.enabled {
            log_invocation(log, &input, &trace);
        }
    }
}

// When approval is enabled and a TUI is alive, route ask/pass-through verdicts through
// the central queue instead of Claude Code's own prompt. Any of: feature off, no live
// TUI, nothing actionable, or operator timeout — falls back to the original trace, i.e.
// today's behavior. The deny/allow paths never reach here.
fn maybe_route_to_approval(
    config: &Config,
    hook_input: &HookInput,
    trace: InvocationTrace,
) -> InvocationTrace {
    if !config.approval.enabled {
        return trace;
    }
    if !matches!(&trace.final_decision, None | Some((Decision::Ask, _))) {
        return trace;
    }

    let dir = queue::state_dir(&config.approval);
    if !queue::is_tui_live_in(&dir, config.approval.heartbeat_fresh_ms()) {
        return trace;
    }

    let nodes = trace.actionable_nodes();
    if nodes.is_empty() {
        return trace;
    }

    let target = request_target(hook_input);
    let request = QueueRequest {
        id: queue::request_id(hook_input.session_id.as_deref().unwrap_or("")),
        ts_ms: log::now_ms(),
        cwd: hook_input.cwd.clone(),
        tool: hook_input.tool_name.clone(),
        target,
        nodes,
    };

    match queue::submit_and_wait_in(
        &dir,
        &request,
        config.approval.self_timeout_ms(),
        config.approval.poll_ms(),
    ) {
        Some(verdict) => {
            let mut trace = trace;
            trace.final_decision = queue::combine_verdict(&verdict.nodes);
            trace
        }
        None => trace,
    }
}

// The one-line label shown for a queued call: its command, URL, search query, or target
// path — falling back to the tool name when the call carries none of those.
fn request_target(hook_input: &HookInput) -> String {
    hook_input
        .tool_input
        .command
        .clone()
        .or_else(|| hook_input.tool_input.url.clone())
        .or_else(|| hook_input.tool_input.query.clone())
        .or_else(|| hook_input.tool_input.file_path.clone())
        .or_else(|| hook_input.tool_input.path.clone())
        .unwrap_or_else(|| hook_input.tool_name.clone())
}

fn print_decision(decision: Decision, reason: &str) {
    let decision_str = match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::Ask => "ask",
    };

    println!(
        "{}",
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision_str,
                "permissionDecisionReason": reason,
            }
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_input_with_cwd() {
        let json =
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/home/user/projects"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.cwd.as_deref(), Some("/home/user/projects"));
    }

    #[test]
    fn hook_input_without_cwd() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.cwd, None);
    }

    #[test]
    fn summary_folds_typed_url_field() {
        let ti: ToolInput = serde_json::from_str(r#"{"url":"https://x.test/page"}"#).unwrap();
        let s = ti.summary();
        assert!(s.contains("url"));
        assert!(s.contains("https://x.test/page"));
    }

    #[test]
    fn summary_keeps_structured_keys() {
        let ti: ToolInput =
            serde_json::from_str(r#"{"fields":[{"name":"Username"},{"name":"Password"}]}"#)
                .unwrap();
        assert!(ti.summary().contains("fields"));
        assert!(ti.summary().contains("Username"));
    }

    #[test]
    fn summary_truncates_long_input() {
        let big = "x".repeat(500);
        let ti: ToolInput = serde_json::from_str(&format!("{{\"blob\":\"{big}\"}}")).unwrap();
        let s = ti.summary();
        assert!(s.chars().count() <= 81, "len was {}", s.chars().count());
        assert!(s.ends_with('…'));
    }

    #[test]
    fn request_target_prefers_command_then_url_then_path() {
        let mut hi = bash_hook_input("ls -la");
        assert_eq!(request_target(&hi), "ls -la");

        hi.tool_input.command = None;
        hi.tool_input.url = Some("https://x.test".into());
        assert_eq!(request_target(&hi), "https://x.test");

        hi = HookInput {
            tool_name: "Edit".into(),
            tool_input: ToolInput {
                command: None,
                url: None,
                query: None,
                file_path: Some("/p/Startup.cs".into()),
                path: None,
                extra: Default::default(),
            },
            cwd: None,
            hook_event_name: None,
            session_id: None,
        };
        assert_eq!(request_target(&hi), "/p/Startup.cs");
    }

    fn bash_hook_input(command: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: ToolInput {
                command: Some(command.into()),
                url: None,
                query: None,
                file_path: None,
                path: None,
                extra: Default::default(),
            },
            cwd: None,
            hook_event_name: None,
            session_id: None,
        }
    }

    // Parity guard: with approval disabled (the default), routing is a no-op — the
    // original verdict is returned verbatim, so the gate behaves exactly as before.
    #[test]
    fn approval_disabled_is_noop() {
        let config = Config::default();
        assert!(!config.approval.enabled);
        let trace = InvocationTrace {
            final_decision: Some((Decision::Ask, "rm is dangerous".into())),
            kind: "command_chain",
            nodes: Vec::new(),
        };
        let out = maybe_route_to_approval(&config, &bash_hook_input("rm foo"), trace);
        assert_eq!(
            out.final_decision.map(|(d, _)| d),
            Some(Decision::Ask),
            "disabled approval must not alter the verdict"
        );
    }
}
