// Configuration model and loading. Rules come from a project-local
// `.claude/lord-kali.toml` (highest priority) merged with all `~/.config/lord-kali/*.toml`
// files in lexicographic order. Patterns are glob by default, regex when wrapped in `//`.

use crate::decision::Decision;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct Config {
    pub(crate) bash: CommandRules,
    pub(crate) powershell: CommandRules,
    pub(crate) web_fetch: PatternRules,
    pub(crate) web_search: PatternRules,
    pub(crate) mcp: McpConfig,
    pub(crate) file: FileConfig,
    pub(crate) log: Option<LogConfig>,
    pub(crate) worktree_protection: WorktreeProtectionConfig,
    pub(crate) approval: ApprovalConfig,
}

impl Config {
    pub(crate) fn merge(mut self, other: Config) -> Config {
        for (cmd, rules) in other.bash.rules {
            self.bash.rules.entry(cmd).or_default().extend(rules);
        }
        for (cmd, rules) in other.powershell.rules {
            self.powershell.rules.entry(cmd).or_default().extend(rules);
        }
        self.web_fetch.rules.extend(other.web_fetch.rules);
        self.web_search.rules.extend(other.web_search.rules);
        self.mcp.rules.extend(other.mcp.rules);
        self.file = self.file.merge(other.file);
        if other.log.is_some() {
            self.log = other.log;
        }
        self.worktree_protection = other.worktree_protection.merge(self.worktree_protection);
        self.approval = self.approval.merge(other.approval);
        self
    }
}

#[derive(Default)]
pub(crate) struct CommandRules {
    pub(crate) rules: HashMap<String, Vec<CommandRule>>,
}

impl CommandRules {
    pub(crate) fn from_raw(
        raw: RawCommandConfig,
        group_projects: &[String],
        source: Source,
    ) -> Self {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();

        for r in raw.rules {
            let decision = match r.decision.as_str() {
                "allow" => Decision::Allow,
                "deny" => Decision::Deny,
                "ask" => Decision::Ask,
                other => panic!("Invalid decision '{}' for command '{}'", other, r.command),
            };
            let projects = merge_and_expand_projects(group_projects, &r.projects);
            let command = r.command;
            let meta = RuleMeta {
                source_file: source.clone(),
                rule_kind: RuleKind::Explicit,
                rule_command: Some(command.clone()),
                rule_args: r.args.clone(),
            };
            rules.entry(command).or_default().push(CommandRule {
                decision,
                args: r.args.map(|a| compile_pattern(&a)),
                reason: r.reason.unwrap_or_else(|| "ok".into()),
                projects,
                meta,
            });
        }

        for cmd in raw.allowed_commands {
            let projects = group_projects.iter().map(|p| expand_tilde(p)).collect();
            let meta = RuleMeta {
                source_file: source.clone(),
                rule_kind: RuleKind::AllowedCommands,
                rule_command: Some(cmd.clone()),
                rule_args: None,
            };
            rules.entry(cmd).or_default().push(CommandRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects,
                meta,
            });
        }

        CommandRules { rules }
    }
}

pub(crate) type Source = Option<Arc<str>>;

#[derive(Clone, Copy, Default, PartialEq)]
pub(crate) enum RuleKind {
    #[default]
    Explicit,
    AllowedCommands,
}

impl RuleKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            RuleKind::Explicit => "explicit",
            RuleKind::AllowedCommands => "allowed_commands",
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct RuleMeta {
    pub(crate) source_file: Source,
    pub(crate) rule_kind: RuleKind,
    pub(crate) rule_command: Option<String>,
    pub(crate) rule_args: Option<String>,
}

pub(crate) struct CommandRule {
    pub(crate) decision: Decision,
    pub(crate) args: Option<Pattern>,
    pub(crate) reason: String,
    pub(crate) projects: Vec<PathBuf>,
    pub(crate) meta: RuleMeta,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawCommandConfig {
    #[serde(default)]
    pub(crate) allowed_commands: Vec<String>,
    #[serde(default)]
    pub(crate) rules: Vec<RawCommandRule>,
}

#[derive(Deserialize)]
pub(crate) struct RawCommandRule {
    pub(crate) command: String,
    pub(crate) args: Option<String>,
    pub(crate) decision: String,
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) projects: Vec<String>,
}

#[derive(Default)]
pub(crate) struct PatternRules {
    pub(crate) rules: Vec<PatternRule>,
}

impl PatternRules {
    pub(crate) fn from_raw(
        raw: RawPatternConfig,
        group_projects: &[String],
        source: Source,
    ) -> Self {
        PatternRules {
            rules: raw
                .rules
                .into_iter()
                .map(|r| {
                    let decision = match r.decision.as_str() {
                        "allow" => Decision::Allow,
                        "deny" => Decision::Deny,
                        "ask" => Decision::Ask,
                        other => panic!("Invalid decision '{}' for pattern '{}'", other, r.pattern),
                    };
                    let projects = merge_and_expand_projects(group_projects, &r.projects);
                    let meta = RuleMeta {
                        source_file: source.clone(),
                        rule_kind: RuleKind::Explicit,
                        rule_command: Some(r.pattern.clone()),
                        rule_args: Some(r.pattern.clone()),
                    };
                    PatternRule {
                        decision,
                        pattern: compile_pattern(&r.pattern),
                        reason: r.reason.unwrap_or_else(|| "ok".into()),
                        projects,
                        meta,
                    }
                })
                .collect(),
        }
    }
}

pub(crate) struct PatternRule {
    pub(crate) decision: Decision,
    pub(crate) pattern: Pattern,
    pub(crate) reason: String,
    pub(crate) projects: Vec<PathBuf>,
    pub(crate) meta: RuleMeta,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawPatternConfig {
    #[serde(default)]
    pub(crate) rules: Vec<RawPatternRule>,
}

// One shared rule shape for single-string pattern gates: web-fetch matches on `url`,
// web-search on `query`. Both deserialize into `pattern`, so the compilation and
// matching logic is written once.
#[derive(Deserialize)]
pub(crate) struct RawPatternRule {
    #[serde(alias = "url", alias = "query")]
    pub(crate) pattern: String,
    pub(crate) decision: String,
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) projects: Vec<String>,
}

// MCP tool-call gating, keyed on the full `mcp__<server>__<tool>` name (glob or /regex/).
// A flat rule list like web-fetch — no args matching; the tool name is the whole key.
#[derive(Default)]
pub(crate) struct McpConfig {
    pub(crate) rules: Vec<McpRule>,
}

impl McpConfig {
    pub(crate) fn from_raw(raw: RawMcpConfig, group_projects: &[String], source: Source) -> Self {
        McpConfig {
            rules: raw
                .rules
                .into_iter()
                .map(|r| {
                    let decision = match r.decision.as_str() {
                        "allow" => Decision::Allow,
                        "deny" => Decision::Deny,
                        "ask" => Decision::Ask,
                        other => panic!("Invalid decision '{}' for mcp tool '{}'", other, r.tool),
                    };
                    let projects = merge_and_expand_projects(group_projects, &r.projects);
                    let meta = RuleMeta {
                        source_file: source.clone(),
                        rule_kind: RuleKind::Explicit,
                        rule_command: Some(r.tool.clone()),
                        rule_args: Some(r.tool.clone()),
                    };
                    McpRule {
                        decision,
                        pattern: compile_pattern(&r.tool),
                        reason: r.reason.unwrap_or_else(|| "ok".into()),
                        projects,
                        meta,
                    }
                })
                .collect(),
        }
    }
}

pub(crate) struct McpRule {
    pub(crate) decision: Decision,
    pub(crate) pattern: Pattern,
    pub(crate) reason: String,
    pub(crate) projects: Vec<PathBuf>,
    pub(crate) meta: RuleMeta,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawMcpConfig {
    #[serde(default)]
    pub(crate) rules: Vec<RawMcpRule>,
}

#[derive(Deserialize)]
pub(crate) struct RawMcpRule {
    pub(crate) tool: String,
    pub(crate) decision: String,
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) projects: Vec<String>,
}

// File-edit gating, keyed on the target path (glob or /regex/). Same flat-rule shape as
// web-fetch — first-match-wins, no args. Opt-in: inert unless `[file] enabled = true`.
#[derive(Default)]
pub(crate) struct FileConfig {
    pub(crate) enabled: bool,
    pub(crate) mutation_scope: MutationScope,
    pub(crate) rules: Vec<FileRule>,
}

// What an unmatched file mutation (Write/Edit/MultiEdit/NotebookEdit) defaults to:
// `All` routes every mutation to the gate so the operator can see and whitelist them;
// `OutsideCwd` only gates mutations whose resolved path escapes cwd (in-cwd passes through).
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub(crate) enum MutationScope {
    #[default]
    All,
    OutsideCwd,
}

impl FileConfig {
    // Opt-in feature: enabling anywhere enables. The scope follows whichever config first
    // turned it on (self is higher priority); rules concatenate, first-match-wins.
    fn merge(mut self, other: Self) -> Self {
        let mutation_scope = if self.enabled {
            self.mutation_scope
        } else {
            other.mutation_scope
        };
        self.rules.extend(other.rules);
        FileConfig {
            enabled: self.enabled || other.enabled,
            mutation_scope,
            rules: self.rules,
        }
    }

    fn from_raw(raw: RawFileConfig, group_projects: &[String], source: Source) -> Self {
        let mutation_scope = match raw.mutation_scope.as_deref() {
            None | Some("all") => MutationScope::All,
            Some("outside_cwd") => MutationScope::OutsideCwd,
            Some(other) => {
                panic!("Invalid mutation_scope '{other}' (use \"all\" or \"outside_cwd\")")
            }
        };
        FileConfig {
            enabled: raw.enabled,
            mutation_scope,
            rules: raw
                .rules
                .into_iter()
                .map(|r| {
                    let decision = match r.decision.as_str() {
                        "allow" => Decision::Allow,
                        "deny" => Decision::Deny,
                        "ask" => Decision::Ask,
                        other => panic!("Invalid decision '{}' for path '{}'", other, r.path),
                    };
                    let projects = merge_and_expand_projects(group_projects, &r.projects);
                    let meta = RuleMeta {
                        source_file: source.clone(),
                        rule_kind: RuleKind::Explicit,
                        rule_command: Some(r.path.clone()),
                        rule_args: Some(r.path.clone()),
                    };
                    FileRule {
                        decision,
                        pattern: compile_pattern(&r.path),
                        reason: r.reason.unwrap_or_else(|| "ok".into()),
                        projects,
                        meta,
                    }
                })
                .collect(),
        }
    }
}

pub(crate) struct FileRule {
    pub(crate) decision: Decision,
    pub(crate) pattern: Pattern,
    pub(crate) reason: String,
    pub(crate) projects: Vec<PathBuf>,
    pub(crate) meta: RuleMeta,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawFileConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    pub(crate) mutation_scope: Option<String>,
    #[serde(default)]
    pub(crate) rules: Vec<RawFileRule>,
}

#[derive(Deserialize)]
pub(crate) struct RawFileRule {
    pub(crate) path: String,
    pub(crate) decision: String,
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) projects: Vec<String>,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawConfig {
    #[serde(default)]
    pub(crate) bash: RawCommandConfig,
    #[serde(default)]
    pub(crate) powershell: RawCommandConfig,
    #[serde(default, rename = "web-fetch")]
    pub(crate) web_fetch: RawPatternConfig,
    #[serde(default, rename = "web-search")]
    pub(crate) web_search: RawPatternConfig,
    #[serde(default)]
    pub(crate) mcp: RawMcpConfig,
    #[serde(default)]
    pub(crate) file: RawFileConfig,
    pub(crate) log: Option<LogConfig>,
    #[serde(default, rename = "worktree-protection")]
    pub(crate) worktree_protection: RawWorktreeProtectionConfig,
    #[serde(default)]
    pub(crate) approval: RawApprovalConfig,
    #[serde(default)]
    pub(crate) group: Vec<RawGroupConfig>,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawGroupConfig {
    #[serde(default)]
    pub(crate) projects: Vec<String>,
    #[serde(default)]
    pub(crate) bash: RawCommandConfig,
    #[serde(default)]
    pub(crate) powershell: RawCommandConfig,
    #[serde(default, rename = "web-fetch")]
    pub(crate) web_fetch: RawPatternConfig,
    #[serde(default, rename = "web-search")]
    pub(crate) web_search: RawPatternConfig,
    #[serde(default)]
    pub(crate) mcp: RawMcpConfig,
    #[serde(default)]
    pub(crate) file: RawFileConfig,
}

impl From<RawConfig> for Config {
    fn from(raw: RawConfig) -> Self {
        Config::from_raw(raw, None)
    }
}

impl Config {
    pub(crate) fn from_raw(raw: RawConfig, source: Source) -> Self {
        let mut bash = CommandRules::from_raw(raw.bash, &[], source.clone());
        let mut powershell = CommandRules::from_raw(raw.powershell, &[], source.clone());
        let mut web_fetch = PatternRules::from_raw(raw.web_fetch, &[], source.clone());
        let mut web_search = PatternRules::from_raw(raw.web_search, &[], source.clone());
        let mut mcp = McpConfig::from_raw(raw.mcp, &[], source.clone());
        let mut file = FileConfig::from_raw(raw.file, &[], source.clone());

        for group in raw.group {
            let group_bash = CommandRules::from_raw(group.bash, &group.projects, source.clone());
            for (cmd, rules) in group_bash.rules {
                bash.rules.entry(cmd).or_default().extend(rules);
            }

            let group_powershell =
                CommandRules::from_raw(group.powershell, &group.projects, source.clone());
            for (cmd, rules) in group_powershell.rules {
                powershell.rules.entry(cmd).or_default().extend(rules);
            }

            let group_web_fetch =
                PatternRules::from_raw(group.web_fetch, &group.projects, source.clone());
            web_fetch.rules.extend(group_web_fetch.rules);

            let group_web_search =
                PatternRules::from_raw(group.web_search, &group.projects, source.clone());
            web_search.rules.extend(group_web_search.rules);

            let group_mcp = McpConfig::from_raw(group.mcp, &group.projects, source.clone());
            mcp.rules.extend(group_mcp.rules);

            let group_file = FileConfig::from_raw(group.file, &group.projects, source.clone());
            file.rules.extend(group_file.rules);
        }

        Config {
            bash,
            powershell,
            web_fetch,
            web_search,
            mcp,
            file,
            log: raw.log,
            worktree_protection: WorktreeProtectionConfig {
                enabled: raw.worktree_protection.enabled,
            },
            approval: ApprovalConfig {
                enabled: raw.approval.enabled,
                live_rules: raw.approval.live_rules,
                state_dir: raw.approval.state_dir,
                guardrail_commands: raw.approval.guardrail_commands,
                self_timeout_ms: raw.approval.self_timeout_ms,
                poll_ms: raw.approval.poll_ms,
                heartbeat_fresh_ms: raw.approval.heartbeat_fresh_ms,
                pending_timeout_ms: raw.approval.pending_timeout_ms,
                watch_poll_ms: raw.approval.watch_poll_ms,
                llm: raw.approval.llm.map(ApprovalLlmConfig::from),
            },
        }
    }
}

fn merge_and_expand_projects(group_projects: &[String], rule_projects: &[String]) -> Vec<PathBuf> {
    let mut seen = Vec::new();
    for p in group_projects.iter().chain(rule_projects.iter()) {
        let expanded = expand_tilde(p);
        if !seen.contains(&expanded) {
            seen.push(expanded);
        }
    }
    seen
}

pub(crate) enum Pattern {
    Glob(String),
    Regex(Regex),
}

impl Pattern {
    pub(crate) fn is_match(&self, text: &str) -> bool {
        match self {
            Pattern::Glob(g) => glob_match_ultra::glob_match(g, text),
            Pattern::Regex(r) => r.is_match(text),
        }
    }
}

pub(crate) fn compile_pattern(s: &str) -> Pattern {
    if let Some(inner) = s.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
        Pattern::Regex(
            Regex::new(&format!("^{inner}$"))
                .unwrap_or_else(|e| panic!("Invalid pattern '{s}': {e}")),
        )
    } else {
        Pattern::Glob(s.to_string())
    }
}

#[derive(Deserialize)]
pub(crate) struct LogConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    pub(crate) path: Option<String>,
}

pub(crate) struct WorktreeProtectionConfig {
    pub(crate) enabled: bool,
}

impl Default for WorktreeProtectionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl WorktreeProtectionConfig {
    fn merge(self, other: Self) -> Self {
        if !self.enabled || !other.enabled {
            Self { enabled: false }
        } else {
            Self { enabled: true }
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct RawWorktreeProtectionConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for RawWorktreeProtectionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// Opt-in central approval. Disabled by default so installing this version never changes
// an existing user's gate behavior. When enabled and a live TUI is present, ask/pass-through
// calls are routed to the TUI queue instead of Claude Code's own prompt.
// Destructive, path-operating commands whose TUI allow/deny-always rules default to a
// tight, path-specific (full-args) scope instead of subcommand scope — so a one-off
// `rm -rf ./tmp` never persists as a blanket `rm -rf` allow. Always on; users extend it.
const DEFAULT_GUARDRAIL: &[&str] = &[
    "rm",
    "rmdir",
    "dd",
    "mkfs",
    "shred",
    "truncate",
    "del",
    "rd",
    "Remove-Item",
    "Clear-Content",
];

// Default approval timers, overridable per `[approval]` key. All in milliseconds.
// Kept below Claude Code's default 60 s hook timeout so a slow operator triggers our own
// pass-through fallback rather than a hard hook timeout.
pub(crate) const DEFAULT_SELF_TIMEOUT_MS: u64 = 50_000;
// How often the blocked gate polls the queue for the TUI's verdict.
pub(crate) const DEFAULT_POLL_MS: u64 = 200;
// A live TUI rewrites its heartbeat every poll; this tolerates a few missed loops without
// ever leaving a closed TUI looking alive (so the gate degrades to pass-through promptly).
pub(crate) const DEFAULT_HEARTBEAT_FRESH_MS: u64 = 3_000;
// How long `watch --tail` tracks a pending call before surfacing it as timed-out (the only
// trace a rejection leaves), and the tail/TUI loop poll cadence.
pub(crate) const DEFAULT_PENDING_TIMEOUT_MS: u64 = 60_000;
pub(crate) const DEFAULT_WATCH_POLL_MS: u64 = 200;

#[derive(Default)]
pub(crate) struct ApprovalConfig {
    pub(crate) enabled: bool,
    pub(crate) live_rules: Option<String>,
    pub(crate) state_dir: Option<String>,
    pub(crate) guardrail_commands: Vec<String>,
    // Approval timers; None => the DEFAULT_* above. Resolved via the accessor methods below.
    pub(crate) self_timeout_ms: Option<u64>,
    pub(crate) poll_ms: Option<u64>,
    pub(crate) heartbeat_fresh_ms: Option<u64>,
    pub(crate) pending_timeout_ms: Option<u64>,
    pub(crate) watch_poll_ms: Option<u64>,
    // Optional LLM auto-approval (Phase 2). None or disabled => the watch never consults a model.
    pub(crate) llm: Option<ApprovalLlmConfig>,
}

impl ApprovalConfig {
    // enabling anywhere enables; an explicit file/dir from a later config overrides;
    // guardrail lists accumulate (union) so protection can only be added, never removed.
    fn merge(mut self, other: Self) -> Self {
        self.guardrail_commands.extend(other.guardrail_commands);
        Self {
            enabled: self.enabled || other.enabled,
            live_rules: other.live_rules.or(self.live_rules),
            state_dir: other.state_dir.or(self.state_dir),
            guardrail_commands: self.guardrail_commands,
            self_timeout_ms: other.self_timeout_ms.or(self.self_timeout_ms),
            poll_ms: other.poll_ms.or(self.poll_ms),
            heartbeat_fresh_ms: other.heartbeat_fresh_ms.or(self.heartbeat_fresh_ms),
            pending_timeout_ms: other.pending_timeout_ms.or(self.pending_timeout_ms),
            watch_poll_ms: other.watch_poll_ms.or(self.watch_poll_ms),
            llm: other.llm.or(self.llm),
        }
    }

    pub(crate) fn live_rules_file(&self) -> &str {
        self.live_rules.as_deref().unwrap_or("99-live.toml")
    }

    pub(crate) fn self_timeout_ms(&self) -> u64 {
        self.self_timeout_ms.unwrap_or(DEFAULT_SELF_TIMEOUT_MS)
    }

    pub(crate) fn poll_ms(&self) -> u64 {
        self.poll_ms.unwrap_or(DEFAULT_POLL_MS)
    }

    pub(crate) fn heartbeat_fresh_ms(&self) -> u64 {
        self.heartbeat_fresh_ms
            .unwrap_or(DEFAULT_HEARTBEAT_FRESH_MS)
    }

    pub(crate) fn pending_timeout_ms(&self) -> u64 {
        self.pending_timeout_ms
            .unwrap_or(DEFAULT_PENDING_TIMEOUT_MS)
    }

    pub(crate) fn watch_poll_ms(&self) -> u64 {
        self.watch_poll_ms.unwrap_or(DEFAULT_WATCH_POLL_MS)
    }

    // Built-in destructive set unioned with the user's additions.
    pub(crate) fn is_guardrail(&self, command: &str) -> bool {
        DEFAULT_GUARDRAIL.contains(&command) || self.guardrail_commands.iter().any(|c| c == command)
    }
}

#[derive(Default, Deserialize)]
pub(crate) struct RawApprovalConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    pub(crate) live_rules: Option<String>,
    pub(crate) state_dir: Option<String>,
    #[serde(default)]
    pub(crate) guardrail_commands: Vec<String>,
    pub(crate) self_timeout_ms: Option<u64>,
    pub(crate) poll_ms: Option<u64>,
    pub(crate) heartbeat_fresh_ms: Option<u64>,
    pub(crate) pending_timeout_ms: Option<u64>,
    pub(crate) watch_poll_ms: Option<u64>,
    pub(crate) llm: Option<RawApprovalLlmConfig>,
}

// Runtime LLM auto-approval (Phase 2). When `enabled` and the watch is running, a passthrough
// request the operator hasn't touched after `queue_wait_ms` is sent to the model; a confident
// `safe` becomes a proposal that auto-applies after `proposal_wait_ms` if still untouched.
// Anything else degrades to passthrough. Timings are sized to fit the 50s hook self-timeout.
pub(crate) struct ApprovalLlmConfig {
    pub(crate) enabled: bool,
    pub(crate) model: String,
    pub(crate) base_url: String,
    // Name of the env var holding the API key (kept out of config files).
    pub(crate) api_key_env: String,
    pub(crate) queue_wait_ms: u64,
    pub(crate) proposal_wait_ms: u64,
    pub(crate) timeout_ms: u64,
    pub(crate) max_attempts: u32,
    // Prompt override; None => the locked default in llm.rs.
    pub(crate) system: Option<String>,
    pub(crate) user: Option<String>,
    // Which tools the model is allowed to judge. The model is a *shell-command* safety
    // gate, so this defaults to Bash/PowerShell; file and other tools are never consulted
    // and ride the operator/timeout fallback instead.
    pub(crate) tools: Vec<String>,
}

impl From<RawApprovalLlmConfig> for ApprovalLlmConfig {
    fn from(r: RawApprovalLlmConfig) -> Self {
        use crate::llm;
        ApprovalLlmConfig {
            enabled: r.enabled,
            model: r.model.unwrap_or_else(|| llm::DEFAULT_MODEL.to_string()),
            base_url: r
                .base_url
                .unwrap_or_else(|| llm::DEFAULT_BASE_URL.to_string()),
            api_key_env: r
                .api_key_env
                .unwrap_or_else(|| "OPENROUTER_API_KEY".to_string()),
            queue_wait_ms: r.queue_wait_ms.unwrap_or(10_000),
            proposal_wait_ms: r.proposal_wait_ms.unwrap_or(5_000),
            timeout_ms: r.timeout_ms.unwrap_or(llm::DEFAULT_TIMEOUT_MS),
            max_attempts: r.max_attempts.unwrap_or(llm::DEFAULT_MAX_ATTEMPTS),
            system: r.system,
            user: r.user,
            tools: r
                .tools
                .unwrap_or_else(|| vec!["Bash".to_string(), "PowerShell".to_string()]),
        }
    }
}

#[derive(Default, Deserialize)]
pub(crate) struct RawApprovalLlmConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    pub(crate) model: Option<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) api_key_env: Option<String>,
    pub(crate) queue_wait_ms: Option<u64>,
    pub(crate) proposal_wait_ms: Option<u64>,
    pub(crate) timeout_ms: Option<u64>,
    pub(crate) max_attempts: Option<u32>,
    pub(crate) system: Option<String>,
    pub(crate) user: Option<String>,
    pub(crate) tools: Option<Vec<String>>,
}

pub(crate) fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(rest)
    } else {
        PathBuf::from(path)
    }
}

pub(crate) fn find_project_config(cwd: &str) -> Option<PathBuf> {
    let mut dir = Path::new(cwd);
    loop {
        let candidate = dir.join(".claude/lord-kali.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir.join(".git").exists() {
            return None;
        }
        dir = dir.parent()?;
    }
}

fn parse_config_file(path: &Path) -> Config {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read config at {}: {}", path.display(), e));
    let raw: RawConfig = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse config at {}: {}", path.display(), e));
    Config::from_raw(raw, Some(Arc::from(path.display().to_string().as_str())))
}

pub(crate) fn lord_kali_config_dir() -> PathBuf {
    dirs::config_dir()
        .expect("Could not determine config directory")
        .join("lord-kali")
}

pub(crate) fn load_config(cwd: Option<&str>) -> Config {
    let initial = cwd
        .and_then(find_project_config)
        .map(|p| parse_config_file(&p))
        .unwrap_or_default();

    let config_dir = lord_kali_config_dir();

    let entries = match std::fs::read_dir(&config_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return initial,
        Err(e) => panic!("Failed to read config dir {}: {}", config_dir.display(), e),
    };

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| parse_config_file(&path))
        .fold(initial, Config::merge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{handle_bash, handle_pattern};

    // --- glob patterns ---

    #[test]
    fn glob_star_single_segment() {
        let p = compile_pattern("https://docs.rs/*");
        assert!(p.is_match("https://docs.rs/foo"));
        assert!(!p.is_match("https://docs.rs/foo/bar"));
        assert!(!p.is_match("https://crates.io/foo"));
    }

    #[test]
    fn glob_doublestar_crosses_segments() {
        let p = compile_pattern("https://docs.rs/**");
        assert!(p.is_match("https://docs.rs/foo"));
        assert!(p.is_match("https://docs.rs/foo/bar/baz"));
        assert!(!p.is_match("https://crates.io/foo"));
    }

    #[test]
    fn glob_question_mark() {
        let p = compile_pattern("ab?");
        assert!(p.is_match("abc"));
        assert!(!p.is_match("abcd"));
    }

    #[test]
    fn glob_character_class() {
        let p = compile_pattern("[a-z]*");
        assert!(p.is_match("hello"));
        assert!(!p.is_match("123"));
    }

    #[test]
    fn glob_brace_expansion() {
        let p = compile_pattern("{allow,deny}");
        assert!(p.is_match("allow"));
        assert!(p.is_match("deny"));
        assert!(!p.is_match("ask"));
    }

    #[test]
    fn glob_brace_with_space_star() {
        let p = compile_pattern("{ls,why,info} *");
        assert!(p.is_match("ls react"));
        assert!(p.is_match("why lodash"));
        assert!(!p.is_match("ls"));
        assert!(!p.is_match("install react"));
    }

    #[test]
    fn glob_doublestar_matches_empty() {
        let p = compile_pattern("**");
        assert!(p.is_match(""));
        assert!(p.is_match("anything"));
        assert!(p.is_match("a/b/c"));
    }

    #[test]
    fn glob_brace_with_space_doublestar() {
        let p = compile_pattern("{fmt,build,test} **");
        assert!(p.is_match("fmt --check"));
        assert!(p.is_match("test /some/path"));
        assert!(!p.is_match("fmt"));
        assert!(!p.is_match("run --release"));
    }

    #[test]
    fn glob_empty_brace_alternation() {
        let p = compile_pattern("{fmt,build,test}{, **}");
        assert!(p.is_match("fmt"));
        assert!(p.is_match("fmt --check"));
        assert!(!p.is_match("run --release"));
    }

    #[test]
    fn glob_doublestar_inside_brace() {
        let p = compile_pattern("{foo, **}");
        assert!(p.is_match("foo"));
        assert!(p.is_match(" a/b/c"));

        let p2 = compile_pattern("test{, **}");
        assert!(p2.is_match("test"));
        assert!(p2.is_match("test --flag"));
        assert!(p2.is_match("test /some/path"));
    }

    #[test]
    fn glob_literal_dot() {
        let p = compile_pattern("example.com");
        assert!(p.is_match("example.com"));
        assert!(!p.is_match("exampleXcom"));
    }

    // --- compile_pattern ---

    #[test]
    fn compile_pattern_glob() {
        let p = compile_pattern("https://docs.rs/**");
        assert!(p.is_match("https://docs.rs/foo"));
        assert!(!p.is_match("https://evil.com/foo"));
    }

    #[test]
    fn compile_pattern_regex() {
        let p = compile_pattern("/https://docs\\.rs/.+/");
        assert!(p.is_match("https://docs.rs/regex/latest"));
        assert!(!p.is_match("https://docs.rs/"));
    }

    // --- group flattening ---

    #[test]
    fn group_projects_applied_to_rules() {
        let raw = RawConfig {
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawPatternConfig::default(),
            web_search: RawPatternConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
            file: RawFileConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec![],
                    rules: vec![RawCommandRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "deny".into(),
                        reason: Some("No publishing".into()),
                        projects: vec![],
                    }],
                },
                powershell: RawCommandConfig::default(),
                web_fetch: RawPatternConfig::default(),
                web_search: RawPatternConfig::default(),
                mcp: RawMcpConfig::default(),
                file: RawFileConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "cargo publish"
            )
            .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/other"),
                "cargo publish"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn group_projects_union_with_rule_projects() {
        let raw = RawConfig {
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawPatternConfig::default(),
            web_search: RawPatternConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
            file: RawFileConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/a".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec![],
                    rules: vec![RawCommandRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "deny".into(),
                        reason: Some("No publishing".into()),
                        projects: vec!["/home/user/projects/b".into()],
                    }],
                },
                powershell: RawCommandConfig::default(),
                web_fetch: RawPatternConfig::default(),
                web_search: RawPatternConfig::default(),
                mcp: RawMcpConfig::default(),
                file: RawFileConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/a"), "cargo publish")
                .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/b"), "cargo publish")
                .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/c"), "cargo publish")
                .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn group_allowed_commands_get_group_projects() {
        let raw = RawConfig {
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawPatternConfig::default(),
            web_search: RawPatternConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
            file: RawFileConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec!["rustup".into()],
                    rules: vec![],
                },
                powershell: RawCommandConfig::default(),
                web_fetch: RawPatternConfig::default(),
                web_search: RawPatternConfig::default(),
                mcp: RawMcpConfig::default(),
                file: RawFileConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "rustup show"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/other"),
                "rustup show"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn group_web_fetch_rules_get_group_projects() {
        let raw = RawConfig {
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawPatternConfig::default(),
            web_search: RawPatternConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
            file: RawFileConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig::default(),
                powershell: RawCommandConfig::default(),
                web_fetch: RawPatternConfig {
                    rules: vec![RawPatternRule {
                        pattern: "https://internal.example.com/**".into(),
                        decision: "allow".into(),
                        reason: Some("ok".into()),
                        projects: vec![],
                    }],
                },
                web_search: RawPatternConfig::default(),
                mcp: RawMcpConfig::default(),
                file: RawFileConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_pattern(
                &config.web_fetch,
                Some("/home/user/projects/test"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_pattern(
                &config.web_fetch,
                Some("/home/user/projects/other"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn top_level_rules_before_group_rules() {
        let raw = RawConfig {
            bash: RawCommandConfig {
                allowed_commands: vec![],
                rules: vec![RawCommandRule {
                    command: "cargo".into(),
                    args: Some("publish{, **}".into()),
                    decision: "deny".into(),
                    reason: Some("Global deny".into()),
                    projects: vec![],
                }],
            },
            powershell: RawCommandConfig::default(),
            web_fetch: RawPatternConfig::default(),
            web_search: RawPatternConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
            file: RawFileConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec![],
                    rules: vec![RawCommandRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "allow".into(),
                        reason: Some("Group allow".into()),
                        projects: vec![],
                    }],
                },
                powershell: RawCommandConfig::default(),
                web_fetch: RawPatternConfig::default(),
                web_search: RawPatternConfig::default(),
                mcp: RawMcpConfig::default(),
                file: RawFileConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "cargo publish"
            ),
            Some((Decision::Deny, "Global deny".into()))
        );
    }

    // --- Config::merge ---

    #[test]
    fn merge_bash_rules() {
        let mut rules_a: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules_a
            .entry("git".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: Some(compile_pattern("status")),
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let a = Config {
            bash: CommandRules { rules: rules_a },
            ..Config::default()
        };

        let mut rules_b: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules_b
            .entry("git".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("push{, **}")),
                reason: "no pushing".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        rules_b
            .entry("cargo".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let b = Config {
            bash: CommandRules { rules: rules_b },
            ..Config::default()
        };

        let merged = a.merge(b);
        let git_rules = &merged.bash.rules["git"];
        assert_eq!(git_rules.len(), 2);
        assert_eq!(git_rules[0].reason, "ok");
        assert_eq!(git_rules[1].reason, "no pushing");
        assert_eq!(merged.bash.rules["cargo"].len(), 1);
    }

    #[test]
    fn merge_web_fetch_rules() {
        let a = Config {
            web_fetch: PatternRules {
                rules: vec![PatternRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://evil.com/**"),
                    reason: "blocked".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                }],
            },
            ..Config::default()
        };
        let b = Config {
            web_fetch: PatternRules {
                rules: vec![PatternRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://docs.rs/**"),
                    reason: "ok".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                }],
            },
            ..Config::default()
        };

        let merged = a.merge(b);
        assert_eq!(merged.web_fetch.rules.len(), 2);
        assert_eq!(merged.web_fetch.rules[0].reason, "blocked");
        assert_eq!(merged.web_fetch.rules[1].reason, "ok");
    }

    #[test]
    fn merge_log_last_wins() {
        let a = Config {
            log: Some(LogConfig {
                enabled: true,
                path: Some("/a.log".into()),
            }),
            ..Config::default()
        };
        let b = Config {
            log: Some(LogConfig {
                enabled: false,
                path: Some("/b.log".into()),
            }),
            ..Config::default()
        };
        let c = Config {
            log: None,
            ..Config::default()
        };

        let merged = a.merge(b);
        assert!(!merged.log.as_ref().unwrap().enabled);
        assert_eq!(merged.log.as_ref().unwrap().path.as_deref(), Some("/b.log"));

        let merged2 = merged.merge(c);
        assert_eq!(
            merged2.log.as_ref().unwrap().path.as_deref(),
            Some("/b.log")
        );
    }

    // --- TOML deserialization ---

    #[test]
    fn toml_top_level_rule_with_projects() {
        let toml_str = r#"
[[bash.rules]]
command = "cargo"
args = "publish{, **}"
decision = "deny"
projects = ["/home/user/projects/test"]
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "cargo publish"
            )
            .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/other"),
                "cargo publish"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn toml_group_with_bash_rules() {
        let toml_str = r#"
[[group]]
projects = ["/home/user/projects/test"]

[group.bash]
allowed_commands = ["rustup"]

[[group.bash.rules]]
command = "cargo"
args = "test{, **}"
decision = "allow"
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/test"), "cargo test")
                .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/other"),
                "cargo test"
            )
            .map(|(d, _)| d),
            None
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "rustup show"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn toml_group_rule_with_extra_projects() {
        let toml_str = r#"
[[group]]
projects = ["/home/user/projects/a"]

[[group.bash.rules]]
command = "make"
decision = "allow"
projects = ["/home/user/projects/b"]
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/a"), "make").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/b"), "make").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/c"), "make").map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn toml_group_web_fetch_rules() {
        let toml_str = r#"
[[group]]
projects = ["/home/user/projects/test"]

[[group.web-fetch.rules]]
url = "https://internal.example.com/**"
decision = "allow"
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            handle_pattern(
                &config.web_fetch,
                Some("/home/user/projects/test"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_pattern(
                &config.web_fetch,
                Some("/home/user/projects/other"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn web_search_rules_parse_via_query_alias() {
        let toml_str = r#"
[[web-search.rules]]
query = "**"
decision = "allow"

[[web-search.rules]]
query = "*password*"
decision = "deny"
reason = "sensitive"
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        // first-match-wins: the allow-all rule precedes the deny, so it takes effect.
        assert_eq!(
            crate::decision::handle_pattern(&config.web_search, None, "anything at all")
                .map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn web_search_deny_when_listed_first() {
        let toml_str = r#"
[[web-search.rules]]
query = "*password*"
decision = "deny"

[[web-search.rules]]
query = "**"
decision = "allow"
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            crate::decision::handle_pattern(&config.web_search, None, "leak the password now")
                .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            crate::decision::handle_pattern(&config.web_search, None, "harmless query")
                .map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    // --- project-local config priority ---

    #[test]
    fn project_config_rules_take_priority_over_global() {
        let project_toml = r#"
[[bash.rules]]
command = "rm"
decision = "deny"
reason = "Project denies rm"
"#;
        let global_toml = r#"
[[bash.rules]]
command = "rm"
decision = "allow"
reason = "Global allows rm"
"#;
        let project_config = {
            let raw: RawConfig = toml::from_str(project_toml).unwrap();
            Config::from(raw)
        };
        let global_config = {
            let raw: RawConfig = toml::from_str(global_toml).unwrap();
            Config::from(raw)
        };

        let merged = project_config.merge(global_config);
        let result = handle_bash(&merged.bash, None, "rm foo");
        assert_eq!(result, Some((Decision::Deny, "Project denies rm".into())));
    }

    // --- find_project_config ---

    #[test]
    fn find_project_config_in_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("lord-kali.toml"), "").unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let result = find_project_config(tmp.path().to_str().unwrap());
        assert_eq!(result, Some(claude_dir.join("lord-kali.toml")));
    }

    #[test]
    fn find_project_config_from_subdirectory() {
        let tmp = tempfile::tempdir().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("lord-kali.toml"), "").unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let sub = tmp.path().join("src/deep");
        std::fs::create_dir_all(&sub).unwrap();

        let result = find_project_config(sub.to_str().unwrap());
        assert_eq!(result, Some(claude_dir.join("lord-kali.toml")));
    }

    #[test]
    fn find_project_config_stops_at_git_root() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let result = find_project_config(tmp.path().to_str().unwrap());
        assert_eq!(result, None);
    }

    #[test]
    fn find_project_config_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("some/path");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let result = find_project_config(sub.to_str().unwrap());
        assert_eq!(result, None);
    }

    // --- worktree protection config ---

    #[test]
    fn worktree_protection_disabled_via_config() {
        let toml_str = r#"
[worktree-protection]
enabled = false
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);
        assert!(!config.worktree_protection.enabled);
    }

    #[test]
    fn worktree_protection_enabled_by_default() {
        let toml_str = "";
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);
        assert!(config.worktree_protection.enabled);
    }

    #[test]
    fn worktree_protection_merge_disabled_wins() {
        let a = Config {
            worktree_protection: WorktreeProtectionConfig { enabled: true },
            ..Config::default()
        };
        let b = Config {
            worktree_protection: WorktreeProtectionConfig { enabled: false },
            ..Config::default()
        };
        let merged = a.merge(b);
        assert!(!merged.worktree_protection.enabled);
    }
}
