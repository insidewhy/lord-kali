// Persists "always" decisions made in the approval TUI to a live ruleset file under
// ~/.config/lord-kali/ (default 99-live.toml, sorted last so it never shadows explicit
// user rules). Each entry is an ordinary [[bash/powershell/web-fetch.rules]] table, scoped
// to the node's subcommand via an args pattern (command-wide only when the node had none).

use crate::config::{lord_kali_config_dir, ApprovalConfig};
use crate::queue::write_atomic;
use std::path::{Path, PathBuf};

pub(crate) struct LiveRule {
    // "bash", "powershell", "web-fetch", "web-search", "mcp", or "file" — picks the rules table.
    pub(crate) shell: String,
    // command basename for bash/powershell; the URL/query pattern for web-fetch/web-search;
    // the MCP tool name, or the path pattern for file.
    pub(crate) target: String,
    // optional args pattern, scoping the rule to a subcommand (e.g. "push{, **}").
    // None means command-wide (any args) — used when the node had no arguments.
    pub(crate) args: Option<String>,
    pub(crate) allow: bool,
}

pub(crate) fn live_rules_path(approval: &ApprovalConfig) -> PathBuf {
    lord_kali_config_dir().join(approval.live_rules_file())
}

fn render_rule(r: &LiveRule) -> String {
    let decision = if r.allow { "allow" } else { "deny" };
    let value = toml::Value::String(r.target.clone()).to_string();
    let (table, key) = match r.shell.as_str() {
        "web-fetch" => ("web-fetch.rules", "url"),
        "web-search" => ("web-search.rules", "query"),
        "powershell" => ("powershell.rules", "command"),
        "mcp" => ("mcp.rules", "tool"),
        "file" => ("file.rules", "path"),
        _ => ("bash.rules", "command"),
    };
    let mut block = format!("\n[[{table}]]\n{key} = {value}\n");
    if let Some(args) = &r.args {
        let av = toml::Value::String(args.clone()).to_string();
        block.push_str(&format!("args = {av}\n"));
    }
    block.push_str(&format!(
        "decision = \"{decision}\"\nreason = \"approval-tui\"\n"
    ));
    block
}

// Append entries to the live file (read-modify-write atomically). Existing rules are
// preserved; an entry whose exact block is already present is skipped, so re-approving
// the same node never piles up duplicates.
pub(crate) fn append_rules(path: &Path, rules: &[LiveRule]) -> std::io::Result<()> {
    if rules.is_empty() {
        return Ok(());
    }
    let mut content = std::fs::read_to_string(path).unwrap_or_default();
    let mut changed = false;
    for r in rules {
        let block = render_rule(r);
        if content.contains(block.trim_start()) {
            continue;
        }
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&block);
        changed = true;
    }
    if changed {
        write_atomic(path, &content)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RawConfig};
    use crate::decision::{handle_bash, handle_mcp, handle_pattern, Decision};

    fn load(path: &Path) -> Config {
        let content = std::fs::read_to_string(path).unwrap();
        let raw: RawConfig = toml::from_str(&content).unwrap();
        Config::from(raw)
    }

    fn bash(target: &str, args: Option<&str>, allow: bool) -> LiveRule {
        LiveRule {
            shell: "bash".into(),
            target: target.into(),
            args: args.map(String::from),
            allow,
        }
    }

    #[test]
    fn command_wide_allow_and_deny_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(&path, &[bash("gh", None, true), bash("curl", None, false)]).unwrap();

        let config = load(&path);
        assert_eq!(
            handle_bash(&config.bash, None, "gh pr list").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, None, "curl https://x").map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    // Subcommand-scoped persistence: allowing `git push` must NOT bless other git verbs.
    #[test]
    fn subcommand_scoped_rule_only_matches_that_subcommand() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(&path, &[bash("git", Some("push{, **}"), true)]).unwrap();

        let config = load(&path);
        assert_eq!(
            handle_bash(&config.bash, None, "git push origin main").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, None, "git push").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        // a different subcommand is untouched by the push rule
        assert_eq!(handle_bash(&config.bash, None, "git commit -m x"), None);
    }

    #[test]
    fn appends_preserve_prior_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(&path, &[bash("gh", None, true)]).unwrap();
        append_rules(&path, &[bash("jq", None, true)]).unwrap();

        let config = load(&path);
        assert_eq!(
            handle_bash(&config.bash, None, "gh pr list").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, None, "jq .").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn identical_rule_is_not_duplicated() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        let rule = || bash("git", Some("push{, **}"), true);
        append_rules(&path, &[rule()]).unwrap();
        append_rules(&path, &[rule()]).unwrap();
        append_rules(&path, &[rule()]).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.matches("[[bash.rules]]").count(), 1);
    }

    #[test]
    fn web_search_persists_query() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(
            &path,
            &[LiveRule {
                shell: "web-search".into(),
                target: "**".into(),
                args: None,
                allow: true,
            }],
        )
        .unwrap();

        let config = load(&path);
        assert_eq!(
            crate::decision::handle_pattern(&config.web_search, None, "any search at all")
                .map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    // A domain-wildcard web-fetch rule matches every path on the host but no other host.
    #[test]
    fn web_fetch_domain_wildcard_matches_host_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(
            &path,
            &[LiveRule {
                shell: "web-fetch".into(),
                target: "https://docs.n8n.io{,/**}".into(),
                args: None,
                allow: true,
            }],
        )
        .unwrap();

        let config = load(&path);
        assert_eq!(
            handle_pattern(&config.web_fetch, None, "https://docs.n8n.io").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_pattern(
                &config.web_fetch,
                None,
                "https://docs.n8n.io/hosting/logging"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_pattern(&config.web_fetch, None, "https://community.n8n.io/t/1"),
            None
        );
    }

    #[test]
    fn web_fetch_persists_url() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(
            &path,
            &[LiveRule {
                shell: "web-fetch".into(),
                target: "https://docs.rs/tokio".into(),
                args: None,
                allow: true,
            }],
        )
        .unwrap();

        let config = load(&path);
        assert_eq!(
            handle_pattern(&config.web_fetch, None, "https://docs.rs/tokio").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn file_persists_path_rule_and_round_trips() {
        use crate::decision::handle_file;
        use crate::ToolInput;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(
            &path,
            &[LiveRule {
                shell: "file".into(),
                target: "/home/u/proj/**".into(),
                args: None,
                allow: true,
            }],
        )
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[[file.rules]]"));
        assert!(content.contains("path = \"/home/u/proj/**\""));
        assert!(!content.contains("args ="), "file rules carry no args");

        // The live file carries only rules; `[file] enabled` lives in the user's config and is
        // OR'd in by the merge — so mirror that here rather than loading the live file alone.
        let base = {
            let raw: RawConfig = toml::from_str("[file]\nenabled = true\n").unwrap();
            Config::from(raw)
        };
        let config = base.merge(load(&path));
        let input = ToolInput {
            command: None,
            url: None,
            query: None,
            file_path: Some("/home/u/proj/src/main.rs".into()),
            path: None,
            extra: Default::default(),
        };
        assert_eq!(
            handle_file(&config.file, "Edit", Some("/home/u/proj"), &input).map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn mcp_persists_tool_name_without_args() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(
            &path,
            &[LiveRule {
                shell: "mcp".into(),
                target: "mcp__playwright__browser_fill_form".into(),
                args: None,
                allow: true,
            }],
        )
        .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[[mcp.rules]]"));
        assert!(content.contains("tool = \"mcp__playwright__browser_fill_form\""));
        assert!(!content.contains("args ="), "mcp rules carry no args scope");

        let config = load(&path);
        assert_eq!(
            handle_mcp(&config.mcp, None, "mcp__playwright__browser_fill_form").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }
}
