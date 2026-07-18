// Command extraction: walk the tree-sitter AST of a bash or PowerShell string and
// pull out every (command basename, args) pair, including those nested in pipelines,
// chains, subshells, command substitutions, script blocks, and xargs wrappers.

pub(crate) fn extract_commands(source: &str) -> Vec<(String, String)> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("Failed to set bash language");

    let tree = parser
        .parse(source, None)
        .expect("Failed to parse bash command");

    let mut commands = Vec::new();
    let mut cursor = tree.root_node().walk();
    walk_node(&mut cursor, source.as_bytes(), &mut commands);
    commands
}

fn extract_args(node: &tree_sitter::Node, source: &[u8]) -> String {
    const REDIRECT_KINDS: &[&str] = &["file_redirect", "heredoc_redirect", "herestring_redirect"];

    let mut parts = Vec::new();
    let mut past_name = false;
    let count = node.child_count();

    for i in 0..count {
        let child = node.child(i).unwrap();
        if !past_name {
            if child.kind() == "command_name" {
                past_name = true;
            }
            continue;
        }
        if REDIRECT_KINDS.contains(&child.kind()) {
            continue;
        }
        if let Ok(text) = child.utf8_text(source) {
            parts.push(text);
        }
    }

    parts.join(" ")
}

fn command_basename(name: &str) -> &str {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.len().checked_sub(4) {
        Some(cut)
            if cut > 0
                && base
                    .get(cut..)
                    .is_some_and(|ext| ext.eq_ignore_ascii_case(".exe")) =>
        {
            &base[..cut]
        }
        _ => base,
    }
}

fn walk_node(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    commands: &mut Vec<(String, String)>,
) {
    let node = cursor.node();

    if node.kind() == "command" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                let basename = command_basename(name);
                if !basename.is_empty() {
                    let args = extract_args(&node, source);
                    commands.push((basename.to_string(), args));

                    if basename == "xargs" {
                        if let Some(sub) = extract_xargs_subcommand(&node, source) {
                            commands.push(sub);
                        }
                    }
                }
            }
        }
    }

    if cursor.goto_first_child() {
        loop {
            walk_node(cursor, source, commands);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn extract_xargs_subcommand(node: &tree_sitter::Node, source: &[u8]) -> Option<(String, String)> {
    const VALUE_FLAGS: &[&str] = &["-d", "-E", "-I", "-L", "-n", "-P", "-s"];

    let mut skip_next = false;
    let mut past_command_name = false;

    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return None;
    }

    loop {
        let child = cursor.node();
        let text = child.utf8_text(source).unwrap_or("");

        if !past_command_name {
            if child.kind() == "command_name" {
                past_command_name = true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
            continue;
        }

        if skip_next {
            skip_next = false;
            if !cursor.goto_next_sibling() {
                break;
            }
            continue;
        }

        if text.starts_with("--") {
            if !cursor.goto_next_sibling() {
                break;
            }
            continue;
        }

        if text.starts_with('-') {
            if VALUE_FLAGS.contains(&text) {
                skip_next = true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
            continue;
        }

        let basename = command_basename(text);
        if !basename.is_empty() {
            let mut sub_args = Vec::new();
            while cursor.goto_next_sibling() {
                let sibling = cursor.node();
                if let Ok(t) = sibling.utf8_text(source) {
                    sub_args.push(t.to_string());
                }
            }
            return Some((basename.to_string(), sub_args.join(" ")));
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }

    None
}

fn strip_surrounding_quotes(token: &str) -> &str {
    let bytes = token.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'\'' || first == b'"') && first == last {
            return &token[1..token.len() - 1];
        }
    }
    token
}

fn quote_aware_tokens(segment: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;

    for c in segment.chars() {
        if let Some(q) = quote {
            current.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }

        match c {
            '\'' | '"' => {
                quote = Some(c);
                current.push(c);
                started = true;
            }
            c if c.is_whitespace() => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        tokens.push(current);
    }
    tokens
}

pub(crate) fn extract_commands_powershell(source: &str) -> Vec<(String, String)> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_powershell::LANGUAGE.into())
        .expect("Failed to set powershell language");

    let tree = parser
        .parse(source, None)
        .expect("Failed to parse powershell command");

    let mut commands = Vec::new();
    let mut cursor = tree.root_node().walk();
    walk_powershell_node(&mut cursor, source.as_bytes(), &mut commands);
    commands
}

fn powershell_command_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let name_node = node
        .children(&mut cursor)
        .find(|c| c.kind() == "command_name" || c.kind() == "command_name_expr")?;
    let raw = name_node.utf8_text(source).ok()?;
    let unquoted = strip_surrounding_quotes(raw);
    let basename = command_basename(unquoted);
    if basename.is_empty() {
        None
    } else {
        Some(basename.to_string())
    }
}

fn powershell_command_args(node: &tree_sitter::Node, source: &[u8]) -> String {
    let mut cursor = node.walk();
    let Some(elements) = node
        .children(&mut cursor)
        .find(|c| c.kind() == "command_elements")
    else {
        return String::new();
    };

    let mut arg_cursor = elements.walk();
    elements
        .children(&mut arg_cursor)
        .filter(|c| c.kind() != "command_argument_sep")
        .filter_map(|c| c.utf8_text(source).ok())
        .collect::<Vec<_>>()
        .join(" ")
}

fn walk_powershell_node(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    commands: &mut Vec<(String, String)>,
) {
    let node = cursor.node();

    if node.kind() == "command" {
        if let Some(name) = powershell_command_name(&node, source) {
            commands.push((name, powershell_command_args(&node, source)));
        }
    } else if node.is_error() {
        if let Some(cmd) = recover_relative_invocation(&node, source) {
            commands.push(cmd);
            // The ERROR subtree is the mis-tokenized fragments of this one invocation,
            // already recovered — descending would only re-walk that garbage.
            return;
        }
    }

    if cursor.goto_first_child() {
        loop {
            walk_powershell_node(cursor, source, commands);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

// tree-sitter-powershell mis-parses a forward-slash relative invocation (`./script.ps1`):
// it reads the leading `.` as the dot-source operator, so no `command` node forms and the
// statement lands in an ERROR subtree. Recover the invocation textually so it is still
// gated rather than silently passed through to Claude Code's own prompt. Scoped to the `./`
// prefix because that is the only form the grammar trips on — `.\x`, `../x`, `scripts/x`,
// `C:/x`, and `& ./x` all parse cleanly as real commands and never reach here. Returns the
// same basename the clean forms yield (extension retained), so a rule gates them identically.
fn recover_relative_invocation(
    node: &tree_sitter::Node,
    source: &[u8],
) -> Option<(String, String)> {
    let text = node.utf8_text(source).ok()?.trim_start();
    if !text.starts_with("./") {
        return None;
    }
    let tokens = quote_aware_tokens(text);
    let (first, rest) = tokens.split_first()?;
    let basename = command_basename(strip_surrounding_quotes(first));
    if basename.is_empty() {
        return None;
    }
    Some((basename.to_string(), rest.join(" ")))
}

const POWERSHELL_EXECUTABLES: &[&str] = &["pwsh", "pwsh.exe", "powershell", "powershell.exe"];

pub(crate) fn inner_powershell_script(name: &str, args: &str) -> Option<String> {
    if !POWERSHELL_EXECUTABLES
        .iter()
        .any(|e| e.eq_ignore_ascii_case(name))
    {
        return None;
    }

    let tokens = quote_aware_tokens(args);
    let idx = tokens
        .iter()
        .position(|t| t.eq_ignore_ascii_case("-command") || t.eq_ignore_ascii_case("-c"))?;

    let rest = &tokens[idx + 1..];
    if rest.is_empty() {
        return None;
    }

    let joined = rest.join(" ");
    Some(strip_surrounding_quotes(&joined).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_names(cmd: &str) -> Vec<String> {
        extract_commands(cmd)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    // --- extract_commands ---

    #[test]
    fn extract_simple_command() {
        assert_eq!(command_names("ls -la"), vec!["ls"]);
    }

    #[test]
    fn extract_pipeline() {
        assert_eq!(command_names("ls | grep foo"), vec!["ls", "grep"]);
    }

    #[test]
    fn extract_and_chain() {
        assert_eq!(command_names("ls && cat foo"), vec!["ls", "cat"]);
    }

    #[test]
    fn extract_or_chain() {
        assert_eq!(command_names("ls || cat foo"), vec!["ls", "cat"]);
    }

    #[test]
    fn extract_semicolon_chain() {
        assert_eq!(command_names("ls; cat foo"), vec!["ls", "cat"]);
    }

    #[test]
    fn extract_command_substitution() {
        assert_eq!(command_names("echo $(rm foo)"), vec!["echo", "rm"]);
    }

    #[test]
    fn extract_subshell() {
        assert_eq!(command_names("(rm foo)"), vec!["rm"]);
    }

    #[test]
    fn extract_path_normalization() {
        assert_eq!(command_names("/usr/bin/rm foo"), vec!["rm"]);
    }

    #[test]
    fn extract_xargs_simple() {
        assert_eq!(
            command_names("find . | xargs rm"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_with_short_value_flag() {
        assert_eq!(
            command_names("find . | xargs -I {} rm {}"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_with_multiple_flags() {
        assert_eq!(
            command_names("find . | xargs -n 1 -I {} rm {}"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_with_long_flag_equals() {
        assert_eq!(
            command_names("find . | xargs --max-procs=4 rm"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_with_boolean_short_flag() {
        assert_eq!(
            command_names("find . | xargs -0 rm"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_subcommand_with_path() {
        assert_eq!(
            command_names("find . | xargs /usr/bin/rm"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_nested_substitution_in_pipeline() {
        let cmds = command_names("find . | ls $(echo poo)");
        assert!(cmds.contains(&"find".to_string()));
        assert!(cmds.contains(&"ls".to_string()));
        assert!(cmds.contains(&"echo".to_string()));
    }

    // --- extract_args ---

    #[test]
    fn extract_args_simple() {
        let cmds = extract_commands("rm -rf /tmp/foo");
        assert_eq!(cmds, vec![("rm".into(), "-rf /tmp/foo".into())]);
    }

    #[test]
    fn extract_args_no_args() {
        let cmds = extract_commands("ls");
        assert_eq!(cmds, vec![("ls".into(), "".into())]);
    }

    #[test]
    fn extract_args_pipeline() {
        let cmds = extract_commands("ls -la | grep foo");
        assert_eq!(
            cmds,
            vec![("ls".into(), "-la".into()), ("grep".into(), "foo".into())]
        );
    }

    #[test]
    fn extract_env_prefix_command() {
        let cmds = extract_commands("PGPASSWORD=secret psql -h localhost mydb");
        assert_eq!(cmds, vec![("psql".into(), "-h localhost mydb".into())]);
    }

    // --- extract_commands_powershell ---

    fn ps_command_names(cmd: &str) -> Vec<String> {
        extract_commands_powershell(cmd)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn ps_extract_simple() {
        assert_eq!(
            extract_commands_powershell("Get-ChildItem"),
            vec![("Get-ChildItem".into(), "".into())]
        );
    }

    #[test]
    fn ps_extract_pipeline() {
        assert_eq!(
            ps_command_names("Get-Process | Stop-Process"),
            vec!["Get-Process", "Stop-Process"]
        );
    }

    #[test]
    fn ps_extract_semicolon() {
        assert_eq!(
            ps_command_names("Get-Foo; Remove-Item x"),
            vec!["Get-Foo", "Remove-Item"]
        );
    }

    #[test]
    fn ps_extract_and_chain() {
        assert_eq!(
            extract_commands_powershell("git status && git push"),
            vec![
                ("git".into(), "status".into()),
                ("git".into(), "push".into())
            ]
        );
    }

    #[test]
    fn ps_extract_call_operator_quoted_path() {
        assert_eq!(
            extract_commands_powershell("& 'C:\\Program Files\\app.exe' --flag"),
            vec![("app".into(), "--flag".into())]
        );
    }

    #[test]
    fn ps_extract_assignment() {
        assert_eq!(
            extract_commands_powershell("$x = Get-Date"),
            vec![("Get-Date".into(), "".into())]
        );
    }

    #[test]
    fn ps_extract_forward_slash_path() {
        assert_eq!(
            extract_commands_powershell("C:/tools/foo.exe bar"),
            vec![("foo".into(), "bar".into())]
        );
    }

    #[test]
    fn ps_extract_comment() {
        assert_eq!(extract_commands_powershell("# comment"), vec![]);
    }

    #[test]
    fn ps_extract_no_split_inside_quotes() {
        assert_eq!(
            ps_command_names("Write-Output 'a | b'"),
            vec!["Write-Output"]
        );
    }

    #[test]
    fn ps_extract_newline_split() {
        assert_eq!(
            ps_command_names("Get-ChildItem\nRemove-Item x"),
            vec!["Get-ChildItem", "Remove-Item"]
        );
    }

    #[test]
    fn ps_extract_script_block() {
        assert_eq!(
            ps_command_names("Get-ChildItem | Where-Object { Remove-Item foo }"),
            vec!["Get-ChildItem", "Where-Object", "Remove-Item"]
        );
    }

    #[test]
    fn ps_extract_command_substitution() {
        assert_eq!(
            ps_command_names("Invoke-Something $(Remove-Item bar)"),
            vec!["Invoke-Something", "Remove-Item"]
        );
    }

    #[test]
    fn ps_extract_assignment_literal_no_command() {
        assert_eq!(
            ps_command_names("$env:NODE_ENV='production'; npm run build"),
            vec!["npm"]
        );
    }

    #[test]
    fn ps_extract_forward_slash_relative_invocation() {
        assert_eq!(
            extract_commands_powershell(
                "./scripts/keyvault/Copy-KeyVaultSecret.ps1 -Name foo -WhatIf"
            ),
            vec![("Copy-KeyVaultSecret.ps1".into(), "-Name foo -WhatIf".into())]
        );
    }

    #[test]
    fn ps_extract_forward_slash_relative_after_assignment() {
        assert_eq!(
            ps_command_names(
                "$x = @(\n  'a',\n  'b'\n)\n./scripts/Copy-KeyVaultSecret.ps1 -TargetVault qa1 -Name $x -WhatIf"
            ),
            vec!["Copy-KeyVaultSecret.ps1"]
        );
    }

    #[test]
    fn ps_extract_forward_slash_relative_after_semicolon() {
        assert_eq!(
            ps_command_names("Get-Foo; ./foo.ps1 -Name bar"),
            vec!["Get-Foo", "foo.ps1"]
        );
    }

    // Path forms the grammar parses cleanly must keep yielding the same single command node
    // (the recovery path is `./`-only and must not double-count or interfere with these).
    #[test]
    fn ps_extract_clean_path_forms_unaffected() {
        assert_eq!(ps_command_names(".\\foo.ps1 -Name x"), vec!["foo.ps1"]);
        assert_eq!(ps_command_names("../foo.ps1 -Name x"), vec!["foo.ps1"]);
        assert_eq!(ps_command_names("scripts/foo.ps1 -Name x"), vec!["foo.ps1"]);
        assert_eq!(
            ps_command_names("C:/scripts/foo.ps1 -Name x"),
            vec!["foo.ps1"]
        );
        assert_eq!(ps_command_names("& ./foo.ps1 -Name x"), vec!["foo.ps1"]);
    }

    #[test]
    fn ps_extract_path_args_preserved() {
        assert_eq!(
            extract_commands_powershell("Get-ChildItem -Path C:\\temp"),
            vec![("Get-ChildItem".into(), "-Path C:\\temp".into())]
        );
    }

    #[test]
    fn command_basename_normalizes_separators_and_exe() {
        assert_eq!(command_basename("rm"), "rm");
        assert_eq!(command_basename("/usr/bin/rm"), "rm");
        assert_eq!(command_basename(r"C:\tools\rm.exe"), "rm");
        assert_eq!(command_basename("git.exe"), "git");
        assert_eq!(command_basename("FOO.EXE"), "FOO");
        assert_eq!(command_basename("Get-ChildItem"), "Get-ChildItem");
        assert_eq!(command_basename(".exe"), ".exe");
    }

    // --- inner_powershell_script ---

    #[test]
    fn inner_ps_command_with_flags() {
        assert_eq!(
            inner_powershell_script("pwsh", "-NoProfile -Command \"Remove-Item x\""),
            Some("Remove-Item x".into())
        );
    }

    #[test]
    fn inner_ps_short_command_flag() {
        assert_eq!(
            inner_powershell_script("powershell", "-c Get-Process"),
            Some("Get-Process".into())
        );
    }

    #[test]
    fn inner_ps_file_returns_none() {
        assert_eq!(inner_powershell_script("pwsh", "-File scripts/x.ps1"), None);
    }

    #[test]
    fn inner_ps_non_powershell_returns_none() {
        assert_eq!(inner_powershell_script("npm", "-Command x"), None);
    }

    #[test]
    fn inner_ps_encoded_command_returns_none() {
        assert_eq!(
            inner_powershell_script("pwsh", "-EncodedCommand UmVtb3ZlLUl0ZW0="),
            None
        );
    }
}
