// The persisted-scope ladder behind the approval TUI's `t` toggle. Each actionable node
// exposes an ordered list of `ScopeRung`s (tightest → broadest); `t` cycles which rung an
// apply-always rule is written at. Command/web/mcp ladders reproduce the prior binary
// tight⇄subcommand behavior exactly; file mutations gain extra rungs (full path → dir
// subtree → cwd subtree → extension glob) so a one-off edit can be whitelisted broadly.
//
// A rung carries the full (target, args) the LiveRule will use: command rungs vary `args`
// and pin `target` to the basename; file/web/mcp rungs vary `target` and carry no `args`.

// Mutating file tools — these get the full multi-rung ladder and route to the gate.
pub(crate) const MUTATION_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];
// Read-class file tools — gated only when the path escapes cwd, persisted at a single
// (full-path) rung, so they never cycle.
pub(crate) const READ_TOOLS: &[&str] = &["Read", "Glob", "Grep"];

pub(crate) fn is_mutation_tool(tool: &str) -> bool {
    MUTATION_TOOLS.contains(&tool)
}

pub(crate) fn is_read_tool(tool: &str) -> bool {
    READ_TOOLS.contains(&tool)
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct ScopeRung {
    pub(crate) target: String,
    pub(crate) args: Option<String>,
}

// Build the ladder for one node plus the default selected index.
// - `shell`: "bash"/"powershell"/"web-fetch"/"mcp"/"file"
// - `tool`: the originating tool name (distinguishes file mutation vs read)
// - `command`: command basename for shells, full URL/tool name for web/mcp, the resolved
//   (forward-slash, absolute) path for file nodes
// - `args`: the command's arguments (ignored for non-shell kinds)
// - `cwd`: the hook cwd, used for the file "cwd subtree" rung
// - `guardrail`: whether a command basename is destructive (defaults its rung to tight)
pub(crate) fn ladder(
    shell: &str,
    tool: &str,
    command: &str,
    args: &str,
    cwd: Option<&str>,
    guardrail: bool,
) -> (Vec<ScopeRung>, usize) {
    match shell {
        "bash" | "powershell" => {
            let tight = ScopeRung {
                target: command.to_string(),
                args: tight_args(args),
            };
            let sub = ScopeRung {
                target: command.to_string(),
                args: scope_args(args),
            };
            let preferred = if guardrail {
                tight.clone()
            } else {
                sub.clone()
            };
            let mut rungs = vec![tight, sub];
            dedup(&mut rungs);
            let default = rungs.iter().position(|r| *r == preferred).unwrap_or(0);
            (rungs, default)
        }
        "file" if is_read_tool(tool) => (vec![full_rung(command)], 0),
        "file" => {
            let path = normalize(command);
            let mut rungs = vec![full_rung(&path)];
            if let Some(dir) = parent_dir(&path) {
                rungs.push(subtree_rung(dir));
            }
            if let Some(c) = cwd.map(normalize) {
                let c = c.trim_end_matches('/');
                if !c.is_empty() && under(&path, c) {
                    rungs.push(subtree_rung(c));
                }
            }
            if let Some(ext) = extension(&path) {
                rungs.push(ScopeRung {
                    target: format!("**/*.{ext}"),
                    args: None,
                });
            }
            dedup(&mut rungs);
            (rungs, 0)
        }
        // web-fetch, mcp, and anything else: one fixed rung, no args — `t` is a no-op.
        _ => (
            vec![ScopeRung {
                target: command.to_string(),
                args: None,
            }],
            0,
        ),
    }
}

fn full_rung(path: &str) -> ScopeRung {
    ScopeRung {
        target: normalize(path),
        args: None,
    }
}

fn subtree_rung(dir: &str) -> ScopeRung {
    ScopeRung {
        target: format!("{dir}/**"),
        args: None,
    }
}

// Scope a command rule to its subcommand: first arg token + trailing wildcard (e.g.
// "push" -> "push{, **}"). None when the node had no args (command-wide).
fn scope_args(args: &str) -> Option<String> {
    let first = args.split_whitespace().next()?;
    Some(format!("{first}{{, **}}"))
}

// Tight (full-args) scope, tolerating extra trailing args. None only when there were none.
fn tight_args(args: &str) -> Option<String> {
    if args.is_empty() {
        None
    } else {
        Some(format!("{args}{{, **}}"))
    }
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

fn parent_dir(path: &str) -> Option<&str> {
    let idx = path.rfind('/')?;
    if idx == 0 {
        None
    } else {
        Some(&path[..idx])
    }
}

fn under(path: &str, dir: &str) -> bool {
    path == dir || path.starts_with(&format!("{dir}/"))
}

// The extension of the final path segment, or None for extensionless / dotfile names.
fn extension(path: &str) -> Option<&str> {
    let seg = path.rsplit('/').next()?;
    let dot = seg.rfind('.')?;
    if dot == 0 || dot + 1 >= seg.len() {
        None
    } else {
        Some(&seg[dot + 1..])
    }
}

// Drop later rungs equal to an earlier one, preserving order. Argless commands and files
// directly in cwd collapse to a single rung this way, making `t` a true no-op there.
fn dedup(rungs: &mut Vec<ScopeRung>) {
    let mut seen: Vec<ScopeRung> = Vec::new();
    rungs.retain(|r| {
        if seen.contains(r) {
            false
        } else {
            seen.push(r.clone());
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rung(target: &str, args: Option<&str>) -> ScopeRung {
        ScopeRung {
            target: target.to_string(),
            args: args.map(String::from),
        }
    }

    #[test]
    fn command_non_guardrail_defaults_to_subcommand() {
        let (rungs, def) = ladder("bash", "Bash", "git", "push origin", None, false);
        assert_eq!(rungs[0], rung("git", Some("push origin{, **}"))); // tight
        assert_eq!(rungs[1], rung("git", Some("push{, **}"))); // subcommand
        assert_eq!(def, 1, "non-guardrail prefers subcommand");
    }

    #[test]
    fn command_guardrail_defaults_to_tight() {
        let (rungs, def) = ladder("bash", "Bash", "rm", "-rf ./out", None, true);
        assert_eq!(def, 0);
        assert_eq!(rungs[def], rung("rm", Some("-rf ./out{, **}")));
    }

    #[test]
    fn argless_command_collapses_to_single_rung() {
        let (rungs, def) = ladder("bash", "Bash", "gh", "", None, false);
        assert_eq!(rungs.len(), 1);
        assert_eq!(rungs[0], rung("gh", None));
        assert_eq!(def, 0);
    }

    // Regression: command rung args must equal the legacy scope_args/tight_args output.
    #[test]
    fn command_rungs_match_legacy_scope() {
        assert_eq!(scope_args("pr list"), Some("pr{, **}".to_string()));
        assert_eq!(scope_args(""), None);
        assert_eq!(tight_args("-rf ./x"), Some("-rf ./x{, **}".to_string()));
        assert_eq!(tight_args(""), None);
    }

    #[test]
    fn web_and_mcp_single_fixed_rung() {
        let (w, dw) = ladder(
            "web-fetch",
            "WebFetch",
            "https://docs.rs/tokio?x=1",
            "",
            None,
            false,
        );
        assert_eq!(w, vec![rung("https://docs.rs/tokio?x=1", None)]);
        assert_eq!(dw, 0);
        let (m, _) = ladder("mcp", "mcp__x__y", "mcp__x__y", "", None, false);
        assert_eq!(m, vec![rung("mcp__x__y", None)]);
    }

    #[test]
    fn file_mutation_full_dir_cwd_ext_ladder() {
        let (rungs, def) = ladder(
            "file",
            "Edit",
            "/home/u/proj/src/app/main.rs",
            "",
            Some("/home/u/proj"),
            false,
        );
        assert_eq!(def, 0);
        assert_eq!(
            rungs,
            vec![
                rung("/home/u/proj/src/app/main.rs", None),
                rung("/home/u/proj/src/app/**", None),
                rung("/home/u/proj/**", None),
                rung("**/*.rs", None),
            ]
        );
    }

    #[test]
    fn file_mutation_windows_path_normalized() {
        let (rungs, _) = ladder(
            "file",
            "Write",
            r"C:\Users\me\proj\Startup.cs",
            "",
            Some(r"C:\Users\me\proj"),
            false,
        );
        // file directly in cwd: dir-subtree and cwd-subtree coincide and dedup to one.
        assert_eq!(
            rungs,
            vec![
                rung("C:/Users/me/proj/Startup.cs", None),
                rung("C:/Users/me/proj/**", None),
                rung("**/*.cs", None),
            ]
        );
    }

    #[test]
    fn file_outside_cwd_has_no_cwd_rung() {
        let (rungs, _) = ladder(
            "file",
            "Edit",
            "/other/repo/x/y.cs",
            "",
            Some("/home/u/proj"),
            false,
        );
        assert_eq!(
            rungs,
            vec![
                rung("/other/repo/x/y.cs", None),
                rung("/other/repo/x/**", None),
                rung("**/*.cs", None),
            ]
        );
    }

    #[test]
    fn file_read_is_single_full_rung() {
        let (rungs, def) = ladder(
            "file",
            "Read",
            "/other/lib/util.rs",
            "",
            Some("/home/u/proj"),
            false,
        );
        assert_eq!(rungs, vec![rung("/other/lib/util.rs", None)]);
        assert_eq!(def, 0);
    }

    #[test]
    fn extensionless_and_dotfiles_have_no_ext_rung() {
        let (rungs, _) = ladder("file", "Edit", "/p/Makefile", "", None, false);
        assert!(rungs.iter().all(|r| !r.target.starts_with("**/*.")));
        let (rungs2, _) = ladder("file", "Edit", "/p/.gitignore", "", None, false);
        assert!(rungs2.iter().all(|r| !r.target.starts_with("**/*.")));
    }
}
