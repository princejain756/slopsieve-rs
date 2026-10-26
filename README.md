# slopsieve-rs

Score a diff or PR for AI-slop review signals. Rust port of [slopsieve](https://github.com/princejain756/slopsieve).

Fifteen weighted checks run over a unified diff: committed secrets, test weakening (`.skip`, `.only`, deleted assertions), debug leftovers, deleted test files, phantom imports, empty catches, trivial dependencies, untested features, commented-out code, narration comments, dead exports, whitespace churn, oversized diffs, vague util sprawl, missing PR context. Scores cap at 100 and land in LOW / MEDIUM / HIGH / ALARM bands.

Suppress a check with `// slopsieve-ignore` in the file or `[slopsieve-ignore: check-id]` in the PR body.

## Usage

```bash
cargo install --path .

git diff main...HEAD | slopsieve
slopsieve patch.diff
slopsieve --format json patch.diff
slopsieve --format github patch.diff   # ::warning annotations for Actions
slopsieve --format sarif patch.diff    # SARIF 2.1.0 for code scanning
slopsieve --strict patch.diff          # exit 1 unless the band is LOW
```

Exit code is the band: 0 LOW, 1 MEDIUM, 2 HIGH, 3 ALARM.

## Layout

- `src/parse.rs` - zero-dependency unified-diff parser (git diffs and plain `diff -u`, CRLF, renames, mode-only changes, `/dev/null`)
- `src/checks.rs` - the 15 checks plus suppression handling
- `src/report.rs` - terminal, JSON, GitHub Actions, and SARIF renderers
- `tests/` - integration tests over `fixtures/`
