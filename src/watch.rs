// `lord-kali watch` tails the JSONL log and prints a colored line per gate decision,
// correlating each pre_tool_use with its post_tool_use so you can see in real time what
// ran, what is awaiting approval, and which command nodes matched no rule.

use crate::log::now_ms;
use std::collections::HashMap;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

// The watcher tidies the log on open and once an hour while running (best-effort).
const PRUNE_INTERVAL_MS: u64 = 3_600_000;

struct Palette {
    color: bool,
}

impl Palette {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }
}

// A PreToolUse decision awaiting its matching PostToolUse. The absence of that match past
// the timeout is the only (noisy) trace a rejection leaves, so we surface it explicitly.
struct PendingPre {
    ts_ms: u64,
    final_decision: String,
    tool: String,
    target: String,
    // For an `ask`, the node in the chain that drove the verdict (`command args — reason`).
    // None for `passthrough` (nothing matched, so nothing "triggered" the rejection).
    deciding: Option<String>,
}

fn event_target(v: &serde_json::Value) -> String {
    let ti = &v["tool_input"];
    for key in ["command", "url", "query", "file_path", "path"] {
        if let Some(s) = ti.get(key).and_then(|x| x.as_str()) {
            return s.to_string();
        }
    }
    String::new()
}

fn correlation_key(v: &serde_json::Value, tool: &str, target: &str) -> String {
    let session = v["session_id"].as_str().unwrap_or("");
    format!("{session}\u{1}{tool}\u{1}{target}")
}

// The specific command node that set the verdict, as `command args — reason`, read from
// lk_decision.deciding. Returns None when nothing matched (deciding is null/absent).
fn format_deciding(lk_decision: &serde_json::Value) -> Option<String> {
    let d = lk_decision.get("deciding")?;
    if d.is_null() {
        return None;
    }
    let cmd = d.get("command").and_then(|x| x.as_str()).unwrap_or("");
    let args = d.get("args").and_then(|x| x.as_str()).unwrap_or("");
    let mut node = cmd.to_string();
    if !args.is_empty() {
        node.push(' ');
        node.push_str(args);
    }
    if let Some(r) = d.get("reason").and_then(|x| x.as_str()) {
        node.push_str(&format!("  — {r}"));
    }
    Some(node)
}

// Command nodes in the chain that matched no rule (`matched: false`) — the gap candidates
// for the allow/deny lists. Empty for an `allow` verdict (every node matched by definition);
// can be non-empty under passthrough/ask/deny. Deduplicated, order preserved.
fn unmatched_nodes(lk_decision: &serde_json::Value) -> Vec<String> {
    let Some(nodes) = lk_decision.get("nodes").and_then(|n| n.as_array()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for n in nodes {
        if n.get("matched").and_then(|m| m.as_bool()) == Some(false) {
            if let Some(cmd) = n.get("command").and_then(|c| c.as_str()) {
                if !cmd.is_empty() && !out.iter().any(|e| e == cmd) {
                    out.push(cmd.to_string());
                }
            }
        }
    }
    out
}

fn render_pre(p: &Palette, tool: &str, target: &str, final_: &str, reason: Option<&str>) -> String {
    let (code, label) = match final_ {
        "allow" => ("32", "ALLOW"),
        "deny" => ("31", "DENY"),
        "ask" => ("33", "ASK"),
        "passthrough" => ("36", "PASS"),
        other => ("0", other),
    };
    let badge = p.paint(code, &format!("{label:<5}"));
    let mut line = format!("{badge}  {tool}: {target}");
    if matches!(final_, "deny" | "ask") {
        if let Some(r) = reason {
            line.push_str(&p.paint("2", &format!("  — {r}")));
        }
    }
    line
}

fn handle_line(p: &Palette, line: &str, pending: &mut HashMap<String, PendingPre>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return;
    };
    let tool = v["tool_name"].as_str().unwrap_or("?").to_string();
    let target = event_target(&v);
    let key = correlation_key(&v, &tool, &target);

    match v["lk_event"].as_str().unwrap_or("") {
        "pre_tool_use" => {
            let final_ = v["lk_decision"]["final"]
                .as_str()
                .unwrap_or("?")
                .to_string();
            let reason = v["lk_decision"]["reason"].as_str();
            let mut out = render_pre(p, &tool, &target, &final_, reason);
            let gaps = unmatched_nodes(&v["lk_decision"]);
            if !gaps.is_empty() {
                out.push_str(&p.paint("36", &format!("   (no rule: {})", gaps.join(", "))));
            }
            println!("{out}");
            let ts_ms = v["ts_ms"].as_u64().unwrap_or_else(now_ms);
            let deciding = format_deciding(&v["lk_decision"]);
            pending.insert(
                key,
                PendingPre {
                    ts_ms,
                    final_decision: final_,
                    tool,
                    target,
                    deciding,
                },
            );
        }
        "post_tool_use" => match pending.remove(&key) {
            // A passthrough/ask that ran is the high-confidence "you approved this" signal.
            Some(pre) if pre.final_decision == "passthrough" || pre.final_decision == "ask" => {
                println!(
                    "{}",
                    p.paint(
                        "32;1",
                        &format!("       └ approved & ran  {tool}: {target}")
                    )
                );
            }
            // An allow always runs; no need to restate it. Drop silently.
            Some(_) => {}
            None => println!(
                "{}",
                p.paint("2", &format!("       · ran  {tool}: {target}"))
            ),
        },
        _ => {}
    }
}

fn sweep_pending(p: &Palette, pending: &mut HashMap<String, PendingPre>, pending_timeout_ms: u64) {
    let now = now_ms();
    let expired: Vec<String> = pending
        .iter()
        .filter(|(_, pre)| now.saturating_sub(pre.ts_ms) > pending_timeout_ms)
        .map(|(k, _)| k.clone())
        .collect();
    for k in expired {
        let pre = pending.remove(&k).unwrap();
        if pre.final_decision == "passthrough" || pre.final_decision == "ask" {
            let mut msg = format!(
                "       └ no execution in {}s — rejected or abandoned?  {}: {}",
                pending_timeout_ms / 1000,
                pre.tool,
                pre.target
            );
            if let Some(node) = &pre.deciding {
                msg.push_str(&format!(
                    "   ({} triggered by: {})",
                    pre.final_decision, node
                ));
            }
            println!("{}", p.paint("35", &msg));
        }
    }
}

// A buffered tail of an append-only file: each read_new() returns the lines appended
// since the previous call. Shared by the plain `--tail` view and the TUI stream.
struct Tailer {
    path: PathBuf,
    offset: u64,
    carry: String,
}

impl Tailer {
    fn new(path: PathBuf) -> Self {
        let offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Tailer {
            path,
            offset,
            carry: String::new(),
        }
    }

    // Skip to the current end of file without emitting anything. Used right after a prune
    // rewrites the log, so the retained history is not replayed into the live stream.
    fn resync_to_end(&mut self) {
        self.offset = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        self.carry.clear();
    }

    fn read_new(&mut self) -> Vec<String> {
        use std::io::{Seek, SeekFrom};
        let mut lines = Vec::new();
        let len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            self.offset = 0;
            self.carry.clear();
        }
        if len > self.offset {
            if let Ok(mut f) = std::fs::File::open(&self.path) {
                if f.seek(SeekFrom::Start(self.offset)).is_ok() {
                    let mut buf = String::new();
                    if let Ok(n) = f.read_to_string(&mut buf) {
                        self.offset += n as u64;
                        self.carry.push_str(&buf);
                        while let Some(idx) = self.carry.find('\n') {
                            let line: String = self.carry.drain(..=idx).collect();
                            let trimmed = line.trim_end();
                            if !trimmed.is_empty() {
                                lines.push(trimmed.to_string());
                            }
                        }
                    }
                }
            }
        }
        lines
    }
}

// `lord-kali watch` opens the interactive approval TUI. `lord-kali watch --tail` keeps
// the original line-by-line tail (logging only, no approval interaction).
pub(crate) fn watch(args: &[String]) {
    let tail_only = args.iter().any(|a| a == "--tail");
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(|s| s.as_str());
    if tail_only {
        watch_tail(path);
    } else if let Err(e) = tui::run(path) {
        eprintln!("lord-kali watch: {e}");
    }
}

fn watch_tail(explicit_path: Option<&str>) {
    let approval = crate::config::load_config(None).approval;
    let pending_timeout_ms = approval.pending_timeout_ms();
    let watch_poll_ms = approval.watch_poll_ms();
    let path = crate::log::resolve_log_path(explicit_path);
    let palette = Palette {
        color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    };

    eprintln!("lord-kali watch --tail — tailing {}", path.display());
    eprintln!(
        "PASS/ASK go to approval; an indented line shows whether they ran. Ctrl-C to stop.\n"
    );

    // Tidy before tailing so retained history is not printed as if it were new.
    let _ = crate::log::prune_log_file(&path, crate::log::DEFAULT_RETAIN_DAYS, now_ms());
    let mut tailer = Tailer::new(path.clone());
    let mut pending: HashMap<String, PendingPre> = HashMap::new();
    let mut next_prune_ms = now_ms() + PRUNE_INTERVAL_MS;

    loop {
        let now = now_ms();
        if now >= next_prune_ms {
            let _ = crate::log::prune_log_file(&path, crate::log::DEFAULT_RETAIN_DAYS, now);
            tailer.resync_to_end();
            next_prune_ms = now + PRUNE_INTERVAL_MS;
        }
        for line in tailer.read_new() {
            handle_line(&palette, &line, &mut pending);
        }
        sweep_pending(&palette, &mut pending, pending_timeout_ms);
        std::thread::sleep(std::time::Duration::from_millis(watch_poll_ms));
    }
}

// The interactive approval TUI: a scrolling decision stream on top, and a pending-approval
// pane below where the operator rules on the actionable command nodes of each blocked call.
mod tui {
    use super::{event_target, unmatched_nodes, Tailer, PRUNE_INTERVAL_MS};
    use crate::config::{load_config, ApprovalConfig, ApprovalLlmConfig};
    use crate::live_rules::{append_rules, live_rules_path, LiveRule};
    use crate::llm::{
        judge, parse_judgement, LlmConfig, PromptTemplate, PromptVars, Verdict as LlmVerdict,
        DEFAULT_BACKOFF_MS, DEFAULT_SYSTEM_PROMPT, DEFAULT_USER_TEMPLATE,
    };
    use crate::log::now_ms;
    use crate::log::{log_event, prune_log_file, resolve_log_path, DEFAULT_RETAIN_DAYS};
    use crate::queue::{
        self, write_atomic, write_heartbeat_in, Action, QueueRequest, Verdict, VerdictNode,
    };
    use crate::scope::{ladder, ScopeRung};
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::layout::{Constraint, Layout, Rect};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Paragraph, Wrap};
    use ratatui::{DefaultTerminal, Frame};
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::time::Duration;

    const STREAM_CAP: usize = 1000;
    // The model-activity buffer is low-volume, so a small cap keeps plenty of history.
    const LLM_STREAM_CAP: usize = 200;
    // A request from a crashed hook (no self-cleanup) is swept after this age.
    const REQ_MAX_AGE_MS: u64 = 120_000;

    // Which lane a node sits in. A commit resolves the whole call: allow the ALLOW lane,
    // deny the DENY lane, and hand ASK nodes back to Claude Code's own prompt (a passthrough,
    // which makes the call defer to the terminal). Default is Allow.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Choice {
        Allow,
        Ask,
        Deny,
    }

    impl Choice {
        // space cycles allow -> ask -> deny -> allow.
        fn cycle(self) -> Choice {
            match self {
                Choice::Allow => Choice::Ask,
                Choice::Ask => Choice::Deny,
                Choice::Deny => Choice::Allow,
            }
        }

        // ←/→ step one lane toward allow / deny (clamped at the ends).
        fn left(self) -> Choice {
            match self {
                Choice::Deny => Choice::Ask,
                _ => Choice::Allow,
            }
        }

        fn right(self) -> Choice {
            match self {
                Choice::Allow => Choice::Ask,
                _ => Choice::Deny,
            }
        }
    }

    struct Pending {
        request: QueueRequest,
        choices: Vec<Choice>,
        // Per node: which rung of its scope ladder an *-always rule persists at. `t` cycles
        // it; the default comes from scope::ladder (tight for guardrail commands and files).
        scope_idx: Vec<usize>,
        cursor: usize,
    }

    impl Pending {
        fn new(request: QueueRequest, approval: &ApprovalConfig) -> Self {
            let choices = vec![Choice::Allow; request.nodes.len()];
            let scope_idx = request
                .nodes
                .iter()
                .map(|n| {
                    ladder(
                        &n.shell,
                        &request.tool,
                        &n.command,
                        &n.args,
                        request.cwd.as_deref(),
                        approval.is_guardrail(&n.command),
                    )
                    .1
                })
                .collect();
            Pending {
                request,
                choices,
                scope_idx,
                cursor: 0,
            }
        }

        // The scope rungs for node `i` (tightest → broadest). The guardrail flag only sets
        // the default index at construction, so it is irrelevant here.
        fn node_rungs(&self, i: usize) -> Vec<ScopeRung> {
            let n = &self.request.nodes[i];
            ladder(
                &n.shell,
                &self.request.tool,
                &n.command,
                &n.args,
                self.request.cwd.as_deref(),
                false,
            )
            .0
        }

        // The rung an *-always rule will persist for node `i`, honoring its `t` selection.
        fn selected_rung(&self, i: usize) -> ScopeRung {
            let rungs = self.node_rungs(i);
            let idx = self.scope_idx[i].min(rungs.len().saturating_sub(1));
            rungs.into_iter().nth(idx).unwrap_or(ScopeRung {
                target: self.request.nodes[i].command.clone(),
                args: None,
            })
        }
    }

    // A commit applies its mode (once = this call only; always = also persist a rule) to
    // every node, using each node's column for the allow/deny direction.
    #[derive(Clone, Copy)]
    enum CommitMode {
        Once,
        Always,
    }

    enum Key {
        Quit,
        Cycle,
        Left,
        Right,
        Up,
        Down,
        PrevReq,
        NextReq,
        ToggleScope,
        Commit(CommitMode),
        SkipCall,
        Ignore,
    }

    fn map_key(code: KeyCode) -> Key {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Key::Quit,
            KeyCode::Char(' ') => Key::Cycle,
            KeyCode::Left | KeyCode::Char('h') => Key::Left,
            KeyCode::Right | KeyCode::Char('l') => Key::Right,
            KeyCode::Up | KeyCode::Char('k') => Key::Up,
            KeyCode::Down | KeyCode::Char('j') => Key::Down,
            KeyCode::Tab => Key::NextReq,
            KeyCode::BackTab => Key::PrevReq,
            KeyCode::Char('t') => Key::ToggleScope,
            KeyCode::Char('a') => Key::Commit(CommitMode::Always),
            KeyCode::Char('o') => Key::Commit(CommitMode::Once),
            KeyCode::Char('s') => Key::SkipCall,
            _ => Key::Ignore,
        }
    }

    struct App {
        stream: Vec<Line<'static>>,
        // Model-activity lines (consult / verdict / auto-approve) live in their own buffer so the
        // high-volume decision stream can't bury or evict them — rendered in a dedicated pane.
        llm_stream: Vec<Line<'static>>,
        pending: Vec<Pending>,
        focus: usize,
        should_quit: bool,
        // Armed by a first Ctrl-C; a second one quits (consistent with Claude Code). Any
        // other key disarms it.
        ctrl_c_armed: bool,
        // Set to the model name when LLM auto-approval is live, for the footer indicator.
        llm_status: Option<String>,
    }

    impl App {
        fn new() -> Self {
            App {
                stream: Vec::new(),
                llm_stream: Vec::new(),
                pending: Vec::new(),
                focus: 0,
                should_quit: false,
                ctrl_c_armed: false,
                llm_status: None,
            }
        }

        fn focused(&self) -> Option<&Pending> {
            self.pending.get(self.focus)
        }

        fn focused_mut(&mut self) -> Option<&mut Pending> {
            self.pending.get_mut(self.focus)
        }
    }

    // Each node resolves by its lane: Allow -> allow, Deny -> deny, Ask -> passthrough
    // (deferred to Claude Code's prompt). The mode picks once vs always; *_always actions
    // persist a rule scoped to the node's currently-selected ladder rung. Ask never persists.
    fn build_verdict(p: &Pending, mode: CommitMode) -> (Verdict, Vec<LiveRule>) {
        let mut nodes = Vec::new();
        let mut live = Vec::new();
        for (i, node) in p.request.nodes.iter().enumerate() {
            let choice = p.choices[i];
            let action = match (choice, mode) {
                (Choice::Allow, CommitMode::Once) => Action::AllowOnce,
                (Choice::Allow, CommitMode::Always) => Action::AllowAlways,
                (Choice::Deny, CommitMode::Once) => Action::DenyOnce,
                (Choice::Deny, CommitMode::Always) => Action::DenyAlways,
                (Choice::Ask, _) => Action::Passthrough,
            };
            if matches!(mode, CommitMode::Always) && choice != Choice::Ask {
                let rung = p.selected_rung(i);
                live.push(LiveRule {
                    shell: node.shell.clone(),
                    target: rung.target,
                    args: rung.args,
                    allow: choice == Choice::Allow,
                });
            }
            nodes.push(VerdictNode {
                command: node.command.clone(),
                args: node.args.clone(),
                action,
            });
        }
        (
            Verdict {
                id: p.request.id.clone(),
                nodes,
            },
            live,
        )
    }

    // Skip the whole call: every node passthrough, nothing persisted — defers the entire
    // call to Claude Code's own prompt, ignoring the lane settings.
    fn build_skip(p: &Pending) -> Verdict {
        Verdict {
            id: p.request.id.clone(),
            nodes: p
                .request
                .nodes
                .iter()
                .map(|n| VerdictNode {
                    command: n.command.clone(),
                    args: n.args.clone(),
                    action: Action::Passthrough,
                })
                .collect(),
        }
    }

    fn apply_key(app: &mut App, key: Key) -> Option<(Verdict, Vec<LiveRule>)> {
        match key {
            Key::Quit => {
                app.should_quit = true;
                None
            }
            Key::Up => {
                if let Some(p) = app.focused_mut() {
                    p.cursor = p.cursor.saturating_sub(1);
                }
                None
            }
            Key::Down => {
                if let Some(p) = app.focused_mut() {
                    if p.cursor + 1 < p.request.nodes.len() {
                        p.cursor += 1;
                    }
                }
                None
            }
            Key::Cycle => {
                if let Some(p) = app.focused_mut() {
                    if let Some(c) = p.choices.get_mut(p.cursor) {
                        *c = c.cycle();
                    }
                }
                None
            }
            Key::Left => {
                if let Some(p) = app.focused_mut() {
                    if let Some(c) = p.choices.get_mut(p.cursor) {
                        *c = c.left();
                    }
                }
                None
            }
            Key::Right => {
                if let Some(p) = app.focused_mut() {
                    if let Some(c) = p.choices.get_mut(p.cursor) {
                        *c = c.right();
                    }
                }
                None
            }
            Key::PrevReq => {
                app.focus = app.focus.saturating_sub(1);
                None
            }
            Key::NextReq => {
                if app.focus + 1 < app.pending.len() {
                    app.focus += 1;
                }
                None
            }
            Key::ToggleScope => {
                if let Some(p) = app.focused_mut() {
                    let cursor = p.cursor;
                    let len = p.node_rungs(cursor).len();
                    if len > 1 {
                        if let Some(idx) = p.scope_idx.get_mut(cursor) {
                            *idx = (*idx + 1) % len;
                        }
                    }
                }
                None
            }
            Key::Commit(mode) => app.focused().map(|p| build_verdict(p, mode)),
            Key::SkipCall => app.focused().map(|p| (build_skip(p), Vec::new())),
            Key::Ignore => None,
        }
    }

    // Surface "waiting for you" on the terminal tab itself (like Claude Code): the window
    // title carries the waiting count, and on Windows Terminal the tab/taskbar icon turns
    // amber (OSC 9;4 state 4) while approvals are pending. Terminals that don't understand
    // a given sequence ignore it.
    fn attention_title(count: usize) -> String {
        if count > 0 {
            format!("● lord-kali — {count} waiting")
        } else {
            "lord-kali — watching".to_string()
        }
    }

    fn set_attention(count: usize) {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = write!(out, "\x1b]0;{}\x07", attention_title(count));
        let state = if count > 0 {
            "\x1b]9;4;4;0\x07"
        } else {
            "\x1b]9;4;0;0\x07"
        };
        let _ = write!(out, "{state}");
        let _ = out.flush();
    }

    fn ring_bell() {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = write!(out, "\x07");
        let _ = out.flush();
    }

    fn clear_attention() {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = write!(out, "\x1b]0;\x07\x1b]9;4;0;0\x07");
        let _ = out.flush();
    }

    // ---- LLM auto-approval (Phase 2) -----------------------------------------------------
    //
    // A passthrough the operator hasn't touched for `queue_wait_ms` is sent to the model on a
    // worker thread (never blocking the TUI). A confident `safe` becomes a Proposed entry that
    // auto-applies — as a TIGHT, persisted allow rule — after `proposal_wait_ms` if still
    // untouched. Any other model outcome (unsafe / malformed / transport error) becomes
    // Declined and the call simply rides out to the hook's own fallback. The model never
    // auto-denies. This whole path is inert unless `[approval.llm] enabled` and the key is set.

    // What a worker thread reports back — full detail so every consult is logged, not just the
    // ones that auto-apply. `kind` is "safe" | "unsafe" | "malformed" | "error"; only a "safe"
    // is actionable (the model never auto-denies).
    struct LlmReport {
        target: String,
        kind: &'static str,
        reason: Option<String>,
        latency_ms: u64,
        detail: Option<String>,
    }

    // Per-request state, keyed by request id so it survives sync_pending rebuilding the list.
    enum LlmPhase {
        Requested,
        Proposed { reason: String, at_ms: u64 },
        Declined,
    }

    // The fields a worker needs, pulled out so spawning doesn't borrow the pending list.
    struct SpawnReq {
        id: String,
        target: String,
        tool: String,
        cwd: Option<String>,
    }

    struct AutoApprover {
        cfg: LlmConfig,
        prompt: PromptTemplate,
        queue_wait_ms: u64,
        proposal_wait_ms: u64,
        // Tools the model is allowed to judge (the LLM-eligibility matcher). The model is a
        // *shell-command* safety gate, so this is Bash/PowerShell by default; file, MCP, and
        // WebFetch calls carry no shell command to reason about and skip the model entirely,
        // riding the operator/hook fallback so they can still be triaged in the TUI.
        tools: Vec<String>,
        tx: Sender<(String, LlmReport)>,
        rx: Receiver<(String, LlmReport)>,
        state: HashMap<String, LlmPhase>,
    }

    impl AutoApprover {
        fn llm_eligible(&self, tool: &str) -> bool {
            self.tools.iter().any(|t| t == tool)
        }
    }

    impl AutoApprover {
        // Build from config + the API key env var. Err (with a reason to surface) when the key
        // is unset, so the caller degrades to today's behavior rather than failing.
        fn from_config(llm: &ApprovalLlmConfig) -> Result<Self, String> {
            let api_key = std::env::var(&llm.api_key_env)
                .ok()
                .filter(|k| !k.is_empty())
                .ok_or_else(|| format!("${} not set", llm.api_key_env))?;
            let (tx, rx) = channel();
            Ok(AutoApprover {
                cfg: LlmConfig {
                    model: llm.model.clone(),
                    base_url: llm.base_url.clone(),
                    api_key,
                    timeout_ms: llm.timeout_ms,
                    max_attempts: llm.max_attempts,
                    backoff_ms: DEFAULT_BACKOFF_MS,
                },
                prompt: PromptTemplate {
                    name: "runtime".into(),
                    system: llm
                        .system
                        .clone()
                        .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string()),
                    user: llm
                        .user
                        .clone()
                        .unwrap_or_else(|| DEFAULT_USER_TEMPLATE.to_string()),
                },
                queue_wait_ms: llm.queue_wait_ms,
                proposal_wait_ms: llm.proposal_wait_ms,
                tools: llm.tools.clone(),
                tx,
                rx,
                state: HashMap::new(),
            })
        }

        fn spawn(&self, s: &SpawnReq) {
            let rendered = self.prompt.render(&PromptVars {
                command: &s.target,
                tool: &s.tool,
                cwd: s.cwd.as_deref().unwrap_or(""),
                policy: "",
            });
            let cfg = self.cfg.clone();
            let id = s.id.clone();
            let target = s.target.clone();
            let tx = self.tx.clone();
            std::thread::spawn(move || {
                let jr = judge(&cfg, &rendered, now_ms);
                let latency_ms = jr.latency_ms;
                let report = match jr.result {
                    Ok(resp) => match parse_judgement(&resp.content) {
                        Ok(j) => LlmReport {
                            target,
                            kind: match j.verdict {
                                LlmVerdict::Safe => "safe",
                                LlmVerdict::Unsafe => "unsafe",
                            },
                            reason: Some(j.reason),
                            latency_ms,
                            detail: None,
                        },
                        Err(e) => LlmReport {
                            target,
                            kind: "malformed",
                            reason: None,
                            latency_ms,
                            detail: Some(e.to_string()),
                        },
                    },
                    Err(e) => LlmReport {
                        target,
                        kind: "error",
                        reason: None,
                        latency_ms,
                        detail: Some(e.to_string()),
                    },
                };
                let _ = tx.send((id, report));
            });
        }

        // Advance the state machine once per loop. Ingests worker results, fires new requests
        // whose queue wait elapsed, and auto-applies proposals whose operator window elapsed
        // (writing the verdict + persisting a tight allow rule + logging). Mutates app.pending.
        // Returns whether it changed anything visible (a stream line or the pending list), so
        // the caller can skip an idle redraw.
        fn tick(
            &mut self,
            app: &mut App,
            qdir: &Path,
            live_path: &Path,
            log_path: &Path,
            now: u64,
        ) -> bool {
            let mut changed = false;
            while let Ok((id, rep)) = self.rx.try_recv() {
                changed = true;
                let proposable = rep.kind == "safe";
                let note = if proposable {
                    format!(
                        "model: SAFE — {} · auto-approve in {}s unless you act",
                        rep.reason.as_deref().unwrap_or(""),
                        self.proposal_wait_ms / 1000
                    )
                } else {
                    format!(
                        "model: {} — {} · passthrough",
                        rep.kind,
                        rep.reason
                            .as_deref()
                            .or(rep.detail.as_deref())
                            .unwrap_or("")
                    )
                };
                push_capped(&mut app.llm_stream, stream_note(&note), LLM_STREAM_CAP);
                if let Some(phase) = self.state.get_mut(&id) {
                    *phase = if proposable {
                        LlmPhase::Proposed {
                            reason: rep.reason.clone().unwrap_or_default(),
                            at_ms: now,
                        }
                    } else {
                        LlmPhase::Declined
                    };
                }
                log_event(
                    log_path,
                    "llm_result",
                    serde_json::json!({
                        "id": id,
                        "model": self.cfg.model,
                        "target": rep.target,
                        "verdict": rep.kind,
                        "reason": rep.reason,
                        "latency_ms": rep.latency_ms,
                        "detail": rep.detail,
                        "will_auto_approve": proposable,
                    }),
                );
            }

            // Forget state for requests the operator resolved or that were swept.
            let live: std::collections::HashSet<String> =
                app.pending.iter().map(|p| p.request.id.clone()).collect();
            self.state.retain(|id, _| live.contains(id));

            let mut to_spawn: Vec<SpawnReq> = Vec::new();
            let mut to_apply: Vec<usize> = Vec::new();
            for (i, p) in app.pending.iter().enumerate() {
                match self.state.get(&p.request.id) {
                    None if self.llm_eligible(&p.request.tool)
                        && now.saturating_sub(p.request.ts_ms) >= self.queue_wait_ms =>
                    {
                        to_spawn.push(SpawnReq {
                            id: p.request.id.clone(),
                            target: p.request.target.clone(),
                            tool: p.request.tool.clone(),
                            cwd: p.request.cwd.clone(),
                        });
                    }
                    Some(LlmPhase::Proposed { at_ms, .. })
                        if now.saturating_sub(*at_ms) >= self.proposal_wait_ms =>
                    {
                        to_apply.push(i);
                    }
                    _ => {}
                }
            }

            changed |= !to_spawn.is_empty();
            for s in &to_spawn {
                self.spawn(s);
                log_event(
                    log_path,
                    "llm_consult",
                    serde_json::json!({
                        "id": s.id,
                        "model": self.cfg.model,
                        "tool": s.tool,
                        "target": s.target,
                        "cwd": s.cwd,
                    }),
                );
                push_capped(
                    &mut app.llm_stream,
                    stream_note(&format!("consulting model on: {}", s.target)),
                    LLM_STREAM_CAP,
                );
                self.state.insert(s.id.clone(), LlmPhase::Requested);
            }

            // Apply highest index first so earlier removals don't shift later indices.
            to_apply.sort_unstable_by(|a, b| b.cmp(a));
            for i in to_apply {
                let reason = match self.state.get(&app.pending[i].request.id) {
                    Some(LlmPhase::Proposed { reason, .. }) => reason.clone(),
                    _ => continue,
                };
                changed = true;
                let p = &mut app.pending[i];
                p.choices = vec![Choice::Allow; p.request.nodes.len()];
                // Auto-approval persists the tightest rung (index 0) — the path/arg-specific rule.
                p.scope_idx = vec![0; p.request.nodes.len()];
                let (verdict, live_rules) = build_verdict(p, CommitMode::Always);

                let vpath = qdir.join(format!("{}.verdict.json", verdict.id));
                if let Ok(j) = serde_json::to_string(&verdict) {
                    let _ = write_atomic(&vpath, &j);
                }
                let _ = append_rules(live_path, &live_rules);
                log_event(
                    log_path,
                    "llm_auto_approve",
                    serde_json::json!({
                        "id": p.request.id.clone(),
                        "tool_name": p.request.tool.clone(),
                        "target": p.request.target.clone(),
                        "cwd": p.request.cwd.clone(),
                        "lk_llm": {
                            "model": self.cfg.model,
                            "verdict": "safe",
                            "reason": reason,
                            "auto_applied": true,
                        },
                    }),
                );
                push_capped(
                    &mut app.llm_stream,
                    stream_note(&format!(
                        "auto-approved (model): {} — {reason}",
                        p.request.target
                    )),
                    LLM_STREAM_CAP,
                );

                let id = p.request.id.clone();
                app.pending.remove(i);
                self.state.remove(&id);
            }
            if app.focus >= app.pending.len() {
                app.focus = app.pending.len().saturating_sub(1);
            }
            changed
        }
    }

    // A dim stream line for model activity, distinct from the gate-decision stream lines.
    fn stream_note(msg: &str) -> Line<'static> {
        Line::from(vec![
            Span::styled(
                "  llm  ",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(msg.to_string(), Style::default().fg(Color::DarkGray)),
        ])
    }

    // Build the auto-approver if configured + enabled + the key is present. On enabled-but-no-key
    // it pushes a one-line warning to the stream and returns None (degrade, never fail).
    fn build_auto(approval: &ApprovalConfig, app: &mut App) -> Option<AutoApprover> {
        let llm = approval.llm.as_ref()?;
        if !llm.enabled {
            return None;
        }
        match AutoApprover::from_config(llm) {
            Ok(a) => {
                app.stream.push(stream_note(&format!(
                    "auto-approval on: {} ({}s queue, {}s proposal)",
                    a.cfg.model,
                    a.queue_wait_ms / 1000,
                    a.proposal_wait_ms / 1000
                )));
                app.llm_status = Some(a.cfg.model.clone());
                Some(a)
            }
            Err(e) => {
                app.stream
                    .push(stream_note(&format!("auto-approval disabled: {e}")));
                None
            }
        }
    }

    // A cheap hash of everything the TUI body/footer renders from structured state (the
    // pending list, focus, per-node selections, and the Ctrl-C arming). The two scrolling
    // buffers are excluded — their content rotates within a fixed cap, so a length/hash can't
    // see new lines; the loop tracks their changes via explicit flags instead. Lets the loop
    // skip a redraw when nothing visible moved, so an idle watcher stops feeding the terminal.
    fn view_revision(app: &App) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        app.pending.len().hash(&mut h);
        app.focus.hash(&mut h);
        app.ctrl_c_armed.hash(&mut h);
        for p in &app.pending {
            p.request.id.hash(&mut h);
            p.cursor.hash(&mut h);
            for c in &p.choices {
                (*c as u8).hash(&mut h);
            }
            p.scope_idx.hash(&mut h);
        }
        h.finish()
    }

    pub(crate) fn run(explicit_path: Option<&str>) -> std::io::Result<()> {
        let cfg = load_config(None);
        let state_dir = queue::state_dir(&cfg.approval);
        let qdir = queue::queue_dir_in(&state_dir);
        let live_path = live_rules_path(&cfg.approval);
        let log_path = resolve_log_path(explicit_path);
        // Tidy on open before tailing so retained history is not replayed into the stream.
        let _ = prune_log_file(&log_path, DEFAULT_RETAIN_DAYS, now_ms());
        let mut tailer = Tailer::new(log_path.clone());

        let mut terminal = ratatui::init();
        let mut app = App::new();
        let mut auto = build_auto(&cfg.approval, &mut app);
        let result = run_loop(
            &mut terminal,
            &mut app,
            &mut tailer,
            &state_dir,
            &qdir,
            &live_path,
            &cfg.approval,
            &log_path,
            &mut auto,
        );
        ratatui::restore();
        clear_attention();
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn run_loop(
        terminal: &mut DefaultTerminal,
        app: &mut App,
        tailer: &mut Tailer,
        state_dir: &Path,
        qdir: &Path,
        live_path: &Path,
        approval: &ApprovalConfig,
        log_path: &Path,
        auto: &mut Option<AutoApprover>,
    ) -> std::io::Result<()> {
        // usize::MAX forces the first iteration to set the title/taskbar without ringing
        // the bell for approvals that were already waiting when the TUI opened.
        let mut prev_pending = usize::MAX;
        // Already pruned once on open; schedule the next housekeeping pass an hour out.
        let mut next_prune_ms = now_ms() + PRUNE_INTERVAL_MS;
        // The view revision last handed to the terminal; None until the first frame. Redraw
        // only when the structured view moved or a scrolling buffer gained a line — an idle
        // watcher then sends the terminal nothing, which is what keeps its memory flat.
        let mut last_rev: Option<u64> = None;
        let poll_ms = approval.watch_poll_ms();
        loop {
            let _ = write_heartbeat_in(state_dir);

            let now = now_ms();
            if now >= next_prune_ms {
                // Best-effort housekeeping; a prune error must never disturb the watch loop.
                let _ = prune_log_file(log_path, DEFAULT_RETAIN_DAYS, now);
                tailer.resync_to_end();
                next_prune_ms = now + PRUNE_INTERVAL_MS;
            }

            let mut dirty = false;
            for line in tailer.read_new() {
                if let Some(l) = stream_line(&line) {
                    push_capped(&mut app.stream, l, STREAM_CAP);
                    dirty = true;
                }
            }

            sync_pending(app, qdir, approval);
            if let Some(a) = auto.as_mut() {
                dirty |= a.tick(app, qdir, live_path, log_path, now);
            }
            let count = app.pending.len();
            if count != prev_pending {
                set_attention(count);
                // Ring once when a new approval arrives (count rose), not on every change.
                if count > prev_pending {
                    ring_bell();
                }
                prev_pending = count;
            }
            let rev = view_revision(app);
            if dirty || Some(rev) != last_rev {
                terminal.draw(|f| ui(f, app))?;
                last_rev = Some(rev);
            }

            if event::poll(Duration::from_millis(poll_ms))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
                    // Ctrl-C-C quits (consistent with Claude Code); first arms, second fires.
                    if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                        if app.ctrl_c_armed {
                            return Ok(());
                        }
                        app.ctrl_c_armed = true;
                        continue;
                    }
                    app.ctrl_c_armed = false;
                    if let Some((verdict, live)) = apply_key(app, map_key(k.code)) {
                        let vpath = qdir.join(format!("{}.verdict.json", verdict.id));
                        if let Ok(j) = serde_json::to_string(&verdict) {
                            let _ = write_atomic(&vpath, &j);
                        }
                        let _ = append_rules(live_path, &live);
                        if app.focus < app.pending.len() {
                            app.pending.remove(app.focus);
                        }
                        if app.focus >= app.pending.len() {
                            app.focus = app.pending.len().saturating_sub(1);
                        }
                    }
                    if app.should_quit {
                        return Ok(());
                    }
                }
            }
        }
    }

    // Reconcile the in-memory pending list with the request files on disk, preserving each
    // item's selection/cursor by id and sweeping requests from hooks that died mid-wait.
    fn sync_pending(app: &mut App, qdir: &Path, approval: &ApprovalConfig) {
        let mut found: Vec<QueueRequest> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(qdir) {
            for e in entries.flatten() {
                let path = e.path();
                let is_req = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".req.json"));
                if !is_req {
                    continue;
                }
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(req) = serde_json::from_str::<QueueRequest>(&s) {
                        if now_ms().saturating_sub(req.ts_ms) > REQ_MAX_AGE_MS {
                            let _ = std::fs::remove_file(&path);
                            continue;
                        }
                        found.push(req);
                    }
                }
            }
        }
        found.sort_by_key(|r| r.ts_ms);

        let mut prev: HashMap<String, (Vec<Choice>, Vec<usize>, usize)> = HashMap::new();
        for p in app.pending.drain(..) {
            prev.insert(p.request.id.clone(), (p.choices, p.scope_idx, p.cursor));
        }
        app.pending = found
            .into_iter()
            .map(|req| match prev.remove(&req.id) {
                Some((choices, scope_idx, cur)) if choices.len() == req.nodes.len() => Pending {
                    cursor: cur.min(req.nodes.len().saturating_sub(1)),
                    choices,
                    scope_idx,
                    request: req,
                },
                _ => Pending::new(req, approval),
            })
            .collect();
        if app.focus >= app.pending.len() {
            app.focus = app.pending.len().saturating_sub(1);
        }
    }

    // Three stacked regions: the stream on top, the approval zone (>= half the screen
    // while there is work), and a help line locked to its own row at the very bottom so a
    // long node list can never push it off-screen.
    fn ui(f: &mut Frame, app: &App) {
        let body = if app.pending.is_empty() {
            Constraint::Length(3)
        } else {
            Constraint::Percentage(55)
        };
        // The model-activity pane only appears when auto-approval is live; sized to its content
        // (up to 6 lines) so it never crowds the decision stream or the approval zone.
        if app.llm_status.is_some() {
            let model_h = (app.llm_stream.len().min(6) as u16 + 2).max(3);
            let [top, model, mid, help] = Layout::vertical([
                Constraint::Min(3),
                Constraint::Length(model_h),
                body,
                Constraint::Length(1),
            ])
            .areas(f.area());
            render_buffer(f, top, "lord-kali — stream", &app.stream);
            render_buffer(f, model, "model activity", &app.llm_stream);
            render_body(f, mid, app);
            render_help(f, help, app);
        } else {
            let [top, mid, help] =
                Layout::vertical([Constraint::Min(3), body, Constraint::Length(1)]).areas(f.area());
            render_buffer(f, top, "lord-kali — stream", &app.stream);
            render_body(f, mid, app);
            render_help(f, help, app);
        }
    }

    // Append to a bounded line buffer, dropping the oldest lines once it exceeds `cap`.
    fn push_capped(buf: &mut Vec<Line<'static>>, line: Line<'static>, cap: usize) {
        buf.push(line);
        if buf.len() > cap {
            let drop = buf.len() - cap;
            buf.drain(0..drop);
        }
    }

    // Render the tail of a line buffer into a bordered box.
    fn render_buffer(f: &mut Frame, area: Rect, title: &str, buf: &[Line<'static>]) {
        let visible = area.height.saturating_sub(2) as usize;
        let start = buf.len().saturating_sub(visible);
        let lines: Vec<Line> = buf[start..].to_vec();
        let para = Paragraph::new(lines)
            .block(Block::bordered().title(title.to_string()))
            .wrap(Wrap { trim: false });
        f.render_widget(para, area);
    }

    fn render_body(f: &mut Frame, area: Rect, app: &App) {
        let Some(p) = app.focused() else {
            let para = Paragraph::new(
                "No pending approvals. ask/pass-through calls appear here while this TUI runs.",
            )
            .block(Block::bordered().title("pending approvals (0)"));
            f.render_widget(para, area);
            return;
        };

        let [header, cols] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(area);

        let mut head = vec![Line::from(vec![
            Span::styled(
                format!("{}: ", p.request.tool),
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw(p.request.target.clone()),
            Span::styled(
                format!("   [call {}/{}]", app.focus + 1, app.pending.len()),
                Style::new().fg(Color::DarkGray),
            ),
        ])];
        head.push(Line::from(Span::styled(
            p.request
                .cwd
                .as_deref()
                .map(|c| format!("cwd {c}"))
                .unwrap_or_default(),
            Style::new().fg(Color::DarkGray),
        )));
        // What an *-always commit would persist for the focused node at its selected ladder
        // rung, so the operator sees the exact rule before pressing a/d.
        if let Some(fnode) = p.request.nodes.get(p.cursor) {
            let rungs = p.node_rungs(p.cursor);
            let idx = p.scope_idx[p.cursor].min(rungs.len().saturating_sub(1));
            let rule_desc = match fnode.shell.as_str() {
                "bash" | "powershell" => match &rungs[idx].args {
                    Some(a) => format!("command=\"{}\" args=\"{}\"", rungs[idx].target, a),
                    None => format!("command=\"{}\"  (any args)", rungs[idx].target),
                },
                "web-fetch" => format!("url=\"{}\"", rungs[idx].target),
                "web-search" => format!("query=\"{}\"", rungs[idx].target),
                "file" => format!("path=\"{}\"", rungs[idx].target),
                _ => format!("tool=\"{}\"", rungs[idx].target),
            };
            let cycle = if rungs.len() > 1 {
                format!("t: rung {}/{} (cycle)", idx + 1, rungs.len())
            } else {
                "exact (no t)".to_string()
            };
            head.push(Line::from(Span::styled(
                format!("→ rule: {rule_desc}   ·  {cycle}"),
                Style::new().fg(if idx == 0 {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            )));
        }
        f.render_widget(Paragraph::new(head), header);

        let [allow_area, ask_area, deny_area] = Layout::horizontal([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .areas(cols);

        let mut lanes: [Vec<Line>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for (i, node) in p.request.nodes.iter().enumerate() {
            let mut style = Style::new();
            if i == p.cursor {
                style = style.add_modifier(Modifier::REVERSED);
            }
            let line = Line::from(Span::styled(
                format!("{} {}", node.command, node.args),
                style,
            ));
            let lane = match p.choices[i] {
                Choice::Allow => 0,
                Choice::Ask => 1,
                Choice::Deny => 2,
            };
            lanes[lane].push(line);
        }
        let [allow_lines, ask_lines, deny_lines] = lanes;

        let lane = |lines: Vec<Line<'static>>, title: String, color: Color| {
            Paragraph::new(lines)
                .block(
                    Block::bordered()
                        .title(title)
                        .border_style(Style::new().fg(color)),
                )
                .wrap(Wrap { trim: false })
        };
        let (na, nk, nd) = (allow_lines.len(), ask_lines.len(), deny_lines.len());
        f.render_widget(
            lane(allow_lines, format!("ALLOW ({na})"), Color::Green),
            allow_area,
        );
        f.render_widget(
            lane(ask_lines, format!("ASK ({nk})"), Color::Yellow),
            ask_area,
        );
        f.render_widget(
            lane(deny_lines, format!("DENY ({nd})"), Color::Red),
            deny_area,
        );
    }

    fn render_help(f: &mut Frame, area: Rect, app: &App) {
        if app.ctrl_c_armed {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "press Ctrl-C again to quit",
                    Style::new().fg(Color::Yellow),
                ))),
                area,
            );
            return;
        }
        let text = if app.pending.is_empty() {
            "q quit · waiting for approvals…"
        } else {
            "space cycle · ←→ lane · ↑↓ node · t scope · ⇥ call · a apply-always · o apply-once · s skip · q quit"
        };
        let mut spans = vec![Span::styled(text, Style::new().fg(Color::DarkGray))];
        match &app.llm_status {
            Some(model) => spans.push(Span::styled(
                format!("   ·   LLM auto-approval active ({model})"),
                Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD),
            )),
            None => spans.push(Span::styled(
                "   ·   LLM auto-approval off",
                Style::new().fg(Color::DarkGray),
            )),
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn stream_line(line: &str) -> Option<Line<'static>> {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        if v["lk_event"].as_str()? != "pre_tool_use" {
            return None;
        }
        let tool = v["tool_name"].as_str().unwrap_or("?").to_string();
        let target = event_target(&v);
        let final_ = v["lk_decision"]["final"].as_str().unwrap_or("?");
        let (label, color) = match final_ {
            "allow" => ("ALLOW".to_string(), Color::Green),
            "deny" => ("DENY".to_string(), Color::Red),
            "ask" => ("ASK".to_string(), Color::Yellow),
            "passthrough" => ("PASS".to_string(), Color::Cyan),
            other => (other.to_string(), Color::Gray),
        };
        let mut spans = vec![
            Span::styled(format!("{label:<5}"), Style::new().fg(color)),
            Span::raw(format!("  {tool}: {target}")),
        ];
        if matches!(final_, "deny" | "ask") {
            if let Some(r) = v["lk_decision"]["reason"].as_str() {
                spans.push(Span::styled(
                    format!("  — {r}"),
                    Style::new().fg(Color::DarkGray),
                ));
            }
        }
        let gaps = unmatched_nodes(&v["lk_decision"]);
        if !gaps.is_empty() {
            spans.push(Span::styled(
                format!("  (no rule: {})", gaps.join(", ")),
                Style::new().fg(Color::Cyan),
            ));
        }
        Some(Line::from(spans))
    }

    #[cfg(test)]
    mod tui_tests {
        use super::*;
        use crate::decision::Decision;
        use crate::queue::{combine_verdict, QueueNode};

        fn req() -> QueueRequest {
            QueueRequest {
                id: "id1".into(),
                ts_ms: 0,
                cwd: None,
                tool: "Bash".into(),
                target: "gh pr list | jq .".into(),
                nodes: vec![
                    QueueNode {
                        shell: "bash".into(),
                        command: "gh".into(),
                        args: "pr list".into(),
                        decision: "passthrough".into(),
                    },
                    QueueNode {
                        shell: "bash".into(),
                        command: "jq".into(),
                        args: ".".into(),
                        decision: "passthrough".into(),
                    },
                ],
            }
        }

        fn pending_app() -> App {
            let mut app = App::new();
            app.pending
                .push(Pending::new(req(), &ApprovalConfig::default()));
            app
        }

        fn rm_request() -> QueueRequest {
            QueueRequest {
                id: "rm1".into(),
                ts_ms: 0,
                cwd: None,
                tool: "Bash".into(),
                target: "rm -rf ./test-results".into(),
                nodes: vec![QueueNode {
                    shell: "bash".into(),
                    command: "rm".into(),
                    args: "-rf ./test-results".into(),
                    decision: "passthrough".into(),
                }],
            }
        }

        // A guardrail command (rm) defaults to the tight rung (index 0, full args); `t`
        // cycles to the broader subcommand rung only when the operator deliberately asks.
        #[test]
        fn guardrail_defaults_tight_and_t_toggles() {
            let mut app = App::new();
            app.pending
                .push(Pending::new(rm_request(), &ApprovalConfig::default()));
            assert_eq!(app.focused().unwrap().scope_idx[0], 0, "rm defaults tight");

            let (_, live) = apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(live[0].args.as_deref(), Some("-rf ./test-results{, **}"));

            apply_key(&mut app, Key::ToggleScope);
            assert_eq!(app.focused().unwrap().scope_idx[0], 1);
            let (_, live2) = apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(live2[0].args.as_deref(), Some("-rf{, **}"));
        }

        // A non-guardrail command defaults to the subcommand rung (index 1, not tight).
        #[test]
        fn non_guardrail_defaults_to_subcommand_scope() {
            let app = pending_app();
            assert_eq!(
                app.focused().unwrap().scope_idx[0],
                1,
                "gh defaults subcommand"
            );
        }

        #[test]
        fn arrows_step_allow_ask_deny() {
            let mut app = pending_app();
            apply_key(&mut app, Key::Right);
            assert_eq!(app.focused().unwrap().choices[0], Choice::Ask);
            apply_key(&mut app, Key::Right);
            assert_eq!(app.focused().unwrap().choices[0], Choice::Deny);
            apply_key(&mut app, Key::Right); // clamped at Deny
            assert_eq!(app.focused().unwrap().choices[0], Choice::Deny);
            apply_key(&mut app, Key::Left);
            assert_eq!(app.focused().unwrap().choices[0], Choice::Ask);
        }

        // gh -> Deny (two steps), jq stays Allow, commit-always: call denies and both
        // lanes persist subcommand-scoped rules.
        #[test]
        fn deny_lane_commit_always_resolves_and_persists() {
            let mut app = pending_app();
            apply_key(&mut app, Key::Right);
            apply_key(&mut app, Key::Right);
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(verdict.nodes[0].action, Action::DenyAlways);
            assert_eq!(verdict.nodes[1].action, Action::AllowAlways);
            assert_eq!(
                combine_verdict(&verdict.nodes).map(|(d, _)| d),
                Some(Decision::Deny)
            );
            assert_eq!(live.len(), 2);
            let gh = live.iter().find(|r| r.target == "gh").unwrap();
            assert!(!gh.allow);
            assert_eq!(gh.args.as_deref(), Some("pr{, **}"));
            assert!(live.iter().find(|r| r.target == "jq").unwrap().allow);
        }

        // An ASK node passes through (defers the whole call) and persists nothing for itself.
        #[test]
        fn ask_lane_defers_call() {
            let mut app = pending_app();
            apply_key(&mut app, Key::Right); // gh -> Ask
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(verdict.nodes[0].action, Action::Passthrough);
            assert_eq!(verdict.nodes[1].action, Action::AllowAlways);
            assert_eq!(combine_verdict(&verdict.nodes), None);
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].target, "jq");
        }

        fn mcp_request() -> QueueRequest {
            QueueRequest {
                id: "mcp1".into(),
                ts_ms: 0,
                cwd: None,
                tool: "mcp__playwright__browser_fill_form".into(),
                target: "mcp__playwright__browser_fill_form".into(),
                nodes: vec![QueueNode {
                    shell: "mcp".into(),
                    command: "mcp__playwright__browser_fill_form".into(),
                    args: r#"{"fields":[{"name":"Password"}]}"#.into(),
                    decision: "passthrough".into(),
                }],
            }
        }

        // MCP nodes have a single fixed rung keyed on the exact tool name — never args.
        #[test]
        fn mcp_node_scope_is_always_none() {
            let (rungs, def) = ladder(
                "mcp",
                "mcp__x__y",
                "mcp__x__y",
                r#"{"fields":[]}"#,
                None,
                false,
            );
            assert_eq!(rungs.len(), 1);
            assert_eq!(def, 0);
            assert!(rungs[0].args.is_none());
            assert_eq!(rungs[0].target, "mcp__x__y");
        }

        #[test]
        fn mcp_allow_always_persists_tool_rule_without_args() {
            let mut app = App::new();
            app.pending
                .push(Pending::new(mcp_request(), &ApprovalConfig::default()));
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(verdict.nodes[0].action, Action::AllowAlways);
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].shell, "mcp");
            assert_eq!(live[0].target, "mcp__playwright__browser_fill_form");
            assert!(live[0].args.is_none());
            assert!(live[0].allow);
        }

        #[test]
        fn mcp_deny_always_persists_deny_without_args() {
            let mut app = App::new();
            app.pending
                .push(Pending::new(mcp_request(), &ApprovalConfig::default()));
            apply_key(&mut app, Key::Right); // -> Ask
            apply_key(&mut app, Key::Right); // -> Deny
            let (_, live) = apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(live.len(), 1);
            assert!(!live[0].allow);
            assert!(live[0].args.is_none());
        }

        #[test]
        fn attention_title_reflects_waiting_count() {
            assert_eq!(attention_title(0), "lord-kali — watching");
            let t = attention_title(3);
            assert!(t.contains("3 waiting"), "got {t}");
            assert!(t.starts_with('●'), "got {t}");
        }

        #[test]
        fn all_allow_once_allows_call_without_persisting() {
            let mut app = pending_app();
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(CommitMode::Once)).expect("commit");
            assert!(live.is_empty());
            assert_eq!(
                combine_verdict(&verdict.nodes).map(|(d, _)| d),
                Some(Decision::Allow)
            );
        }

        // Global skip overrides the lanes: every node passthrough, nothing persisted.
        #[test]
        fn skip_call_passes_everything_through() {
            let mut app = pending_app();
            apply_key(&mut app, Key::Right);
            apply_key(&mut app, Key::Right); // gh -> Deny, would otherwise deny
            let (verdict, live) = apply_key(&mut app, Key::SkipCall).expect("skip");
            assert!(verdict
                .nodes
                .iter()
                .all(|n| n.action == Action::Passthrough));
            assert!(live.is_empty());
            assert_eq!(combine_verdict(&verdict.nodes), None);
        }

        fn one_node_request(shell: &str, target: &str) -> QueueRequest {
            QueueRequest {
                id: "u1".into(),
                ts_ms: 0,
                cwd: None,
                tool: if shell == "web-search" {
                    "WebSearch".into()
                } else {
                    "WebFetch".into()
                },
                target: target.into(),
                nodes: vec![QueueNode {
                    shell: shell.into(),
                    command: target.into(),
                    args: String::new(),
                    decision: "passthrough".into(),
                }],
            }
        }

        fn commit_target(shell: &str, target: &str, toggle: bool) -> String {
            let mut app = App::new();
            app.pending.push(Pending::new(
                one_node_request(shell, target),
                &ApprovalConfig::default(),
            ));
            if toggle {
                apply_key(&mut app, Key::ToggleScope);
            }
            let (_, live) = apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(live.len(), 1);
            assert!(
                live[0].args.is_none(),
                "url/query rules never scope by args"
            );
            live[0].target.clone()
        }

        // Under the ladder, web-fetch and web-search each have a single fixed rung — the exact
        // target, no args — so `t` is a no-op and persistence is the literal URL/query either way.
        #[test]
        fn web_fetch_persists_exact_url() {
            let url = "https://docs.n8n.io/hosting/logging";
            assert_eq!(commit_target("web-fetch", url, false), url);
            assert_eq!(commit_target("web-fetch", url, true), url);
        }

        #[test]
        fn web_search_persists_exact_query() {
            let q = "n8n /healthz/readiness live database query";
            assert_eq!(commit_target("web-search", q, false), q);
            assert_eq!(commit_target("web-search", q, true), q);
        }

        #[test]
        fn renders_without_panic() {
            use ratatui::backend::TestBackend;
            use ratatui::Terminal;
            let mut app = pending_app();
            apply_key(&mut app, Key::Right); // exercise the ASK lane + cursor highlight
            app.stream.push(Line::raw("ALLOW  Bash: ls"));
            let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
            terminal.draw(|f| ui(f, &app)).unwrap();
            // also exercise the idle (no-pending) layout
            let idle = App::new();
            terminal.draw(|f| ui(f, &idle)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmatched_nodes_lists_dedup_in_order() {
        let d = serde_json::json!({
            "nodes": [
                {"command": "ls", "matched": true},
                {"command": "cargo", "matched": false},
                {"command": "frob", "matched": false},
                {"command": "cargo", "matched": false},
            ]
        });
        assert_eq!(unmatched_nodes(&d), vec!["cargo", "frob"]);
    }

    #[test]
    fn unmatched_nodes_empty_when_all_matched() {
        let d = serde_json::json!({
            "nodes": [
                {"command": "ls", "matched": true},
                {"command": "cat", "matched": true},
            ]
        });
        assert!(unmatched_nodes(&d).is_empty());
    }

    #[test]
    fn format_deciding_renders_node_and_reason() {
        let d = serde_json::json!({
            "deciding": {"command": "rm", "args": "-rf foo", "reason": "Recursive/force delete — confirm."}
        });
        assert_eq!(
            format_deciding(&d).as_deref(),
            Some("rm -rf foo  — Recursive/force delete — confirm.")
        );
    }

    #[test]
    fn format_deciding_null_is_none() {
        let d = serde_json::json!({ "deciding": serde_json::Value::Null });
        assert_eq!(format_deciding(&d), None);
    }
}
