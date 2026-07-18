// JSONL logging. Best-effort: any failure here is swallowed so a gate decision already
// printed to Claude Code is never blocked or altered by a logging problem.

use crate::config::{expand_tilde, load_config, LogConfig};
use crate::decision::{deciding_index, InvocationTrace};
use crate::queue::write_atomic;
use std::path::{Path, PathBuf};

pub(crate) const DEFAULT_LOG_PATH: &str = "~/.local/state/lord-kali/hook.jsonl";
// Log entries older than this are dropped by `prune-logs` and the watch housekeeper.
pub(crate) const DEFAULT_RETAIN_DAYS: u64 = 3;

fn append_log_line(log_config: &LogConfig, line: String) {
    let path_str = log_config.path.as_deref().unwrap_or(DEFAULT_LOG_PATH);
    append_line_to_path(&expand_tilde(path_str), line);
}

// Best-effort append to an explicit log path. Any IO failure is swallowed (logging never
// blocks a gate or, here, an auto-approval).
fn append_line_to_path(path: &Path, line: String) {
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    use std::io::Write;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = writeln!(file, "{}", line);
}

// Append an LLM auto-approval observability event to the log, stamped with ts_ms + lk_event.
// The watch builds the field set (so this stays a thin, generic sink), letting it record the
// full lifecycle — `llm_consult` (model asked), `llm_result` (what it replied + latency), and
// `llm_auto_approve` (applied) — so `watch --tail` and audits can see if/what/when it decided.
// Best-effort: a logging failure never blocks an auto-approval.
pub(crate) fn log_event(path: &Path, event: &str, fields: serde_json::Value) {
    let mut fields = fields;
    if let Some(obj) = fields.as_object_mut() {
        obj.insert("ts_ms".to_string(), serde_json::json!(now_ms()));
        obj.insert("lk_event".to_string(), serde_json::json!(event));
    }
    append_line_to_path(path, fields.to_string());
}

pub(crate) fn log_invocation(log_config: &LogConfig, input: &str, trace: &InvocationTrace) {
    append_log_line(log_config, timestamped_log_line(input, trace));
}

// PostToolUse fires only after a tool actually executed (auto-allowed or user-approved
// at the prompt). It cannot gate, so this path only logs, with no decision and no stdout.
pub(crate) fn log_post_tool_use(log_config: &LogConfig, input: &str) {
    append_log_line(log_config, post_tool_use_log_line(input));
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// Resolve the active log path: an explicit override (tilde-expanded), else the configured
// `[log] path`, else the default. Shared by the watcher and `prune-logs` so both agree.
pub(crate) fn resolve_log_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return expand_tilde(p);
    }
    let config = load_config(None);
    let path_str = config
        .log
        .as_ref()
        .and_then(|l| l.path.as_deref())
        .unwrap_or(DEFAULT_LOG_PATH);
    expand_tilde(path_str)
}

fn entry_ts_ms(line: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("ts_ms")?
        .as_u64()
}

// Drop entries older than `max_age_days`, rewriting the file atomically. Lines whose ts_ms
// can't be parsed are kept (we never silently discard data we can't date). A missing file
// is a no-op. Returns (kept, removed). Best-effort callers (the watcher) ignore the result.
pub(crate) fn prune_log_file(
    path: &Path,
    max_age_days: u64,
    now_ms: u64,
) -> std::io::Result<(usize, usize)> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(e) => return Err(e),
    };
    let cutoff = now_ms.saturating_sub(max_age_days.saturating_mul(86_400_000));
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if entry_ts_ms(line).is_none_or(|ts| ts >= cutoff) {
            kept.push(line);
        } else {
            removed += 1;
        }
    }
    if removed > 0 {
        let mut out = kept.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        write_atomic(path, &out)?;
    }
    Ok((kept.len(), removed))
}

// `lord-kali prune-logs [--days N] [path]`: drop log entries older than N days (default 7).
pub(crate) fn prune_logs_cli(args: &[String]) {
    let mut days = DEFAULT_RETAIN_DAYS;
    let mut path_arg: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--days" => {
                days = match it.next().and_then(|d| d.parse().ok()) {
                    Some(n) => n,
                    None => {
                        eprintln!("lord-kali prune-logs: --days requires a number");
                        std::process::exit(2);
                    }
                };
            }
            s if s.starts_with("--") => {
                eprintln!("lord-kali prune-logs: unknown flag {s}");
                std::process::exit(2);
            }
            s => path_arg = Some(s),
        }
    }
    let path = resolve_log_path(path_arg);
    match prune_log_file(&path, days, now_ms()) {
        Ok((kept, removed)) => println!(
            "lord-kali prune-logs: removed {removed}, kept {kept} (retained < {days}d) in {}",
            path.display()
        ),
        Err(e) => {
            eprintln!("lord-kali prune-logs: {}: {e}", path.display());
            std::process::exit(1);
        }
    }
}

// Parse the hook input into an object, stamp ts_ms + lk_event, then let the caller add
// event-specific fields. Non-object input is passed through trimmed.
fn shape_log_line(
    input: &str,
    event: &str,
    add_fields: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> String {
    match serde_json::from_str::<serde_json::Value>(input) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.insert("ts_ms".to_string(), serde_json::json!(now_ms()));
            map.insert("lk_event".to_string(), serde_json::json!(event));
            add_fields(&mut map);
            serde_json::Value::Object(map).to_string()
        }
        _ => input.trim().to_string(),
    }
}

fn post_tool_use_log_line(input: &str) -> String {
    shape_log_line(input, "post_tool_use", |map| {
        map.remove("tool_response");
    })
}

fn decision_breakdown(trace: &InvocationTrace) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    let final_str = match &trace.final_decision {
        Some((d, _)) => d.as_str(),
        None => "passthrough",
    };
    obj.insert("final".into(), serde_json::json!(final_str));
    obj.insert("kind".into(), serde_json::json!(trace.kind));
    if let Some((_, reason)) = &trace.final_decision {
        obj.insert("reason".into(), serde_json::json!(reason));
    }

    match deciding_index(&trace.nodes) {
        Some(i) => obj.insert("deciding".into(), trace.nodes[i].to_json()),
        None => obj.insert("deciding".into(), serde_json::Value::Null),
    };

    let nodes: Vec<serde_json::Value> = trace.nodes.iter().map(|n| n.to_json()).collect();
    obj.insert("nodes".into(), serde_json::Value::Array(nodes));
    serde_json::Value::Object(obj)
}

fn timestamped_log_line(input: &str, trace: &InvocationTrace) -> String {
    shape_log_line(input, "pre_tool_use", |map| {
        map.insert("lk_decision".to_string(), decision_breakdown(trace));
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{empty_trace, InvocationTrace};

    fn empty_invocation_trace() -> InvocationTrace {
        InvocationTrace {
            final_decision: None,
            kind: "command_chain",
            nodes: Vec::new(),
        }
    }

    #[test]
    fn timestamped_log_line_injects_ts_and_preserves_fields() {
        let line = timestamped_log_line(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x"}"#,
            &empty_invocation_trace(),
        );
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["tool_name"], "Bash");
        assert_eq!(v["tool_input"]["command"], "ls");
        assert_eq!(v["cwd"], "/x");
        assert!(v["ts_ms"].as_u64().unwrap() > 0);
        assert_eq!(v["lk_decision"]["final"], "passthrough");
    }

    #[test]
    fn timestamped_log_line_passes_through_non_object() {
        assert_eq!(
            timestamped_log_line("not json", &empty_invocation_trace()),
            "not json"
        );
    }

    #[test]
    fn post_tool_use_line_marks_event_and_strips_response() {
        let input = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x","session_id":"s1","tool_response":{"stdout":"a","stderr":""}}"#;
        let line = post_tool_use_log_line(input);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["lk_event"], serde_json::json!("post_tool_use"));
        assert_eq!(v["tool_name"], serde_json::json!("Bash"));
        assert_eq!(v["tool_input"]["command"], serde_json::json!("ls"));
        assert_eq!(v["session_id"], serde_json::json!("s1"));
        assert!(v.get("tool_response").is_none());
        assert!(v.get("ts_ms").is_some());
        assert!(v.get("lk_decision").is_none());
    }

    #[test]
    fn pre_tool_use_line_marks_event() {
        let input = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x"}"#;
        let trace = empty_trace("command_chain");
        let line = timestamped_log_line(input, &trace);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["lk_event"], serde_json::json!("pre_tool_use"));
        assert!(v.get("lk_decision").is_some());
    }

    // --- prune_log_file ---

    const NOW: u64 = 1_000_000_000_000;
    const DAY_MS: u64 = 86_400_000;

    #[test]
    fn prune_drops_old_keeps_recent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hook.jsonl");
        let old = format!(r#"{{"ts_ms":{},"x":"old"}}"#, NOW - 8 * DAY_MS);
        let recent = format!(r#"{{"ts_ms":{},"x":"recent"}}"#, NOW - DAY_MS);
        std::fs::write(&path, format!("{old}\n{recent}\n")).unwrap();

        assert_eq!(prune_log_file(&path, 7, NOW).unwrap(), (1, 1));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("recent"));
        assert!(!content.contains("old"));
        assert!(content.ends_with('\n'));
    }

    // Lines we can't date are kept — pruning never silently discards unparseable data.
    #[test]
    fn prune_keeps_lines_without_ts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hook.jsonl");
        std::fs::write(&path, "not json\n{\"no\":\"ts\"}\n").unwrap();
        assert_eq!(prune_log_file(&path, 7, NOW).unwrap(), (2, 0));
    }

    #[test]
    fn prune_missing_file_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("absent.jsonl");
        assert_eq!(prune_log_file(&path, 7, NOW).unwrap(), (0, 0));
        assert!(!path.exists());
    }

    #[test]
    fn prune_without_removals_leaves_file_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hook.jsonl");
        let recent = format!("{{\"ts_ms\":{},\"x\":\"r\"}}\n", NOW - 1000);
        std::fs::write(&path, &recent).unwrap();
        assert_eq!(prune_log_file(&path, 7, NOW).unwrap(), (1, 0));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), recent);
    }
}
