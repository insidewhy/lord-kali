# CLAUDE.md

This file provides guidance to LLM agents when working with code in this repository.

## Core principles

The implementation must strictly adhere to these non-negotiable principles, as established in previous PRDs:

1. **DRY (don't Repeat yourself)**

   - Zero code duplication will be tolerated
   - Each functionality must exist in exactly one place
   - No duplicate files or alternative implementations allowed

2. **KISS (keep it simple, stupid)**

   - Implement the simplest solution that works
   - No over-engineering or unnecessary complexity
   - Straightforward, maintainable code patterns

3. **Clean file system**

   - All existing files must be either used or removed
   - No orphaned, redundant, or unused files
   - Clear, logical organization of the file structure

4. **Transparent error handling**

   - All errors must be properly displayed to the user; errors must be clear, actionable, and honest
   - No error hiding: never swallow or mask a genuine failure
   - **Deliberate graceful degradation is not error hiding.** Documented fallback paths that keep the gate safe and agents unblocked — degrading to pass-through when no approval TUI is alive, self-timing-out below Claude Code's hook timeout, and best-effort logging that never blocks a gate decision — are part of the design. Such paths must be explicit and commented as deliberate, and must never paper over a genuine error.

5. **No obvious comments**

   - Code comments that can easily be inferred by a reasonably competent engineer are unnecessary, they create more lines of code without aiding understanding.

## Success Criteria

In accordance with the established principles and previous PRDs, the implementation will be successful if:

1. **Zero Duplication**: No duplicate code or files exist in the codebase
2. **Single Implementation**: Each feature has exactly one implementation
3. **No Silent Masking**: No fallback hides or masks a genuine error; deliberate degradation paths are documented (see principle 4)
4. **Transparent Errors**: All errors are properly displayed to users
5. **Modular Architecture**: Responsibilities are split into focused modules (`config`, `parse`, `decision`, `worktree`, `log`, `watch`, `queue`, `live_rules`)

## Code Style

- Format code with `cargo fmt`
- Keep `cargo test` green and `cargo clippy` clean

## Build & install

`make install` (build release + copy to `~/.local/bin/lord-kali`) is the canonical flow, but
`make` is not available on Windows. The equivalent steps:

```powershell
cargo build --release
Copy-Item target\release\lord-kali.exe (Join-Path $HOME ".local\bin\lord-kali.exe") -Force
```

Runtime changes (anything under `watch`, the LLM gate, decision/parse logic) only take effect
once the installed binary is replaced — the per-command hook and `lord-kali watch` both run the
copy at `~/.local/bin/lord-kali.exe`, not the build output.

**The copy fails while `lord-kali watch` is running** — Windows locks the running exe
(`The process cannot access the file ... being used by another process`). Stop the watch, copy,
then restart it.
