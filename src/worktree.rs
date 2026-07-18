// Worktree protection: when cwd is inside `<parent>/.claude/worktrees/<name>`, deny
// file tool calls that target the parent project, steering them to the worktree copy.

use crate::decision::Decision;
use crate::ToolInput;

const WORKTREE_SEGMENT: &str = "/.claude/worktrees/";

pub(crate) fn detect_worktree(cwd: &str) -> Option<(&str, &str)> {
    // Match the segment regardless of separator (Windows cwds use `\`). Replacing `\`
    // with `/` preserves byte offsets, so indices stay valid against the original `cwd`.
    let normalized = cwd.replace('\\', "/");
    let idx = normalized.find(WORKTREE_SEGMENT)?;
    let after = &normalized[idx + WORKTREE_SEGMENT.len()..];
    if after.is_empty() || after.ends_with('/') {
        return None;
    }
    Some((&cwd[..idx], cwd))
}

const FILE_TOOLS: &[&str] = &[
    "Read",
    "Write",
    "Edit",
    "Glob",
    "Grep",
    "NotebookEdit",
    "MultiEdit",
];

pub(crate) fn check_worktree_protection(
    cwd: &str,
    tool_name: &str,
    tool_input: &ToolInput,
) -> Option<(Decision, String)> {
    if !FILE_TOOLS.contains(&tool_name) {
        return None;
    }

    let (parent_root, worktree_root) = detect_worktree(cwd)?;

    let file_path = tool_input
        .file_path
        .as_deref()
        .or(tool_input.path.as_deref())?;

    // Compare with separators normalized so a `\`-vs-`/` mismatch between cwd and the
    // tool's path can't defeat the check. Normalization preserves byte length, so
    // `parent_root.len()` stays a valid offset into the original `file_path`.
    let file_norm = file_path.replace('\\', "/");
    if file_norm.starts_with(&worktree_root.replace('\\', "/")) {
        return None;
    }

    if !file_norm.starts_with(&parent_root.replace('\\', "/")) {
        return None;
    }

    let relative = &file_path[parent_root.len()..];
    let corrected = format!("{worktree_root}{relative}");

    Some((
        Decision::Deny,
        format!(
            "You are in a worktree. Do not read/write the parent project at {parent_root}. \
             Use the worktree path instead: {corrected}"
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- detect_worktree ---

    #[test]
    fn detect_worktree_valid() {
        let (parent, worktree) =
            detect_worktree("/home/user/projects/myapp/.claude/worktrees/feature-x").unwrap();
        assert_eq!(parent, "/home/user/projects/myapp");
        assert_eq!(
            worktree,
            "/home/user/projects/myapp/.claude/worktrees/feature-x"
        );
    }

    #[test]
    fn detect_worktree_not_a_worktree() {
        assert!(detect_worktree("/home/user/projects/myapp").is_none());
    }

    #[test]
    fn detect_worktree_trailing_slash_in_worktrees_dir() {
        assert!(detect_worktree("/home/user/projects/myapp/.claude/worktrees/").is_none());
    }

    #[test]
    fn detect_worktree_multi_segment_name() {
        let (parent, worktree) =
            detect_worktree("/home/user/projects/myapp/.claude/worktrees/fix/PJ-1234").unwrap();
        assert_eq!(parent, "/home/user/projects/myapp");
        assert_eq!(
            worktree,
            "/home/user/projects/myapp/.claude/worktrees/fix/PJ-1234"
        );
    }

    #[test]
    fn detect_worktree_windows_separators() {
        let (parent, worktree) =
            detect_worktree(r"C:\Users\me\proj\.claude\worktrees\feature-x").unwrap();
        assert_eq!(parent, r"C:\Users\me\proj");
        assert_eq!(worktree, r"C:\Users\me\proj\.claude\worktrees\feature-x");
    }

    #[test]
    fn detect_worktree_windows_trailing_separator() {
        assert!(detect_worktree(r"C:\Users\me\proj\.claude\worktrees\").is_none());
    }

    // --- check_worktree_protection ---

    fn worktree_tool_input(file_path: Option<&str>, path: Option<&str>) -> ToolInput {
        ToolInput {
            command: None,
            url: None,
            query: None,
            file_path: file_path.map(String::from),
            path: path.map(String::from),
            extra: Default::default(),
        }
    }

    #[test]
    fn worktree_denies_read_from_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/home/user/project/src/main.rs"), None);
        let result = check_worktree_protection(cwd, "Read", &input);
        assert!(result.is_some());
        let (decision, reason) = result.unwrap();
        assert_eq!(decision, Decision::Deny);
        assert!(reason.contains("/home/user/project/.claude/worktrees/feat/src/main.rs"));
    }

    #[test]
    fn worktree_denies_write_from_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/home/user/project/Cargo.toml"), None);
        let result = check_worktree_protection(cwd, "Write", &input);
        assert!(result.is_some());
        let (decision, reason) = result.unwrap();
        assert_eq!(decision, Decision::Deny);
        assert!(reason.contains("/home/user/project/.claude/worktrees/feat/Cargo.toml"));
    }

    #[test]
    fn worktree_denies_edit_from_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/home/user/project/src/lib.rs"), None);
        let result = check_worktree_protection(cwd, "Edit", &input);
        assert!(result.is_some());
    }

    #[test]
    fn worktree_denies_grep_path_from_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(None, Some("/home/user/project/src"));
        let result = check_worktree_protection(cwd, "Grep", &input);
        assert!(result.is_some());
        let (_, reason) = result.unwrap();
        assert!(reason.contains("/home/user/project/.claude/worktrees/feat/src"));
    }

    #[test]
    fn worktree_allows_file_within_worktree() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(
            Some("/home/user/project/.claude/worktrees/feat/src/main.rs"),
            None,
        );
        let result = check_worktree_protection(cwd, "Read", &input);
        assert!(result.is_none());
    }

    #[test]
    fn worktree_allows_file_outside_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/tmp/something.txt"), None);
        let result = check_worktree_protection(cwd, "Read", &input);
        assert!(result.is_none());
    }

    #[test]
    fn worktree_ignores_non_file_tools() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/home/user/project/src/main.rs"), None);
        assert!(check_worktree_protection(cwd, "Bash", &input).is_none());
        assert!(check_worktree_protection(cwd, "WebFetch", &input).is_none());
    }

    #[test]
    fn worktree_no_file_path_passthrough() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(None, None);
        assert!(check_worktree_protection(cwd, "Read", &input).is_none());
    }

    #[test]
    fn worktree_denies_parent_path_windows() {
        let input = worktree_tool_input(Some(r"C:\Users\me\proj\src\main.rs"), None);
        let result =
            check_worktree_protection(r"C:\Users\me\proj\.claude\worktrees\feat", "Read", &input);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, Decision::Deny);
    }
}
