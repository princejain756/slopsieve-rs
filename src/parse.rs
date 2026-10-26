//! Minimal unified-diff parser. Handles git diffs AND plain `diff -u` output,
//! CRLF, timestamps, quoted paths, mode-only changes, renames, and empty files.
//! Hunk boundaries come from the `@@ -o,c +n,c @@` counts, so a removed line
//! starting with "-- " can't be mistaken for a "--- " file header.

use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct DiffLine {
    pub text: String,
    pub line: usize,
}

#[derive(Debug, Default)]
pub struct FileDiff {
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    pub is_new: bool,
    pub is_deleted: bool,
    pub adds: Vec<DiffLine>,
    pub dels: Vec<DiffLine>,
    pub ctxs: Vec<DiffLine>,
}

impl FileDiff {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path(&self) -> &str {
        static UNKNOWN: &str = "(unknown)";
        self.new_path
            .as_deref()
            .or(self.old_path.as_deref())
            .unwrap_or(UNKNOWN)
    }
}

fn strip(p: &str) -> String {
    let p = p.split('\t').next().unwrap_or("").trim();
    let p = p.trim_matches('"');
    p.strip_prefix("a/")
        .or_else(|| p.strip_prefix("b/"))
        .unwrap_or(p)
        .to_string()
}

static HUNK_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@").unwrap()
});

static GIT_HEADER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^diff --git "?a/(.+?)"? "?b/(.+?)"?$"#).unwrap());

struct Hunk {
    old_start: usize,
    new_start: usize,
    old_left: i64,
    new_left: i64,
    old_count: usize,
    new_count: usize,
}

impl Hunk {
    fn open(&self) -> bool {
        self.old_left > 0 || self.new_left > 0
    }
}

pub fn parse_diff(text: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut cur_idx: Option<usize> = None;
    let mut hunk: Option<Hunk> = None;

    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let open = hunk.as_ref().map(|h| h.open()).unwrap_or(false);

        if !open && raw.starts_with("diff --git ") {
            let mut f = FileDiff::new();
            if let Some(m) = GIT_HEADER_RE.captures(raw) {
                f.old_path = Some(strip(&m[1]));
                f.new_path = Some(strip(&m[2]));
            }
            files.push(f);
            cur_idx = Some(files.len() - 1);
            hunk = None;
            continue;
        }

        let f = match cur_idx {
            Some(i) => &mut files[i],
            None => {
                if !open && raw.starts_with("--- ") {
                    // plain `diff -u` with no diff --git header
                    files.push(FileDiff::new());
                    let i = files.len() - 1;
                    cur_idx = Some(i);
                    &mut files[i]
                } else {
                    continue;
                }
            }
        };

        if !open && raw.starts_with("new file mode") {
            f.is_new = true;
            continue;
        }
        if !open && raw.starts_with("deleted file mode") {
            f.is_deleted = true;
            continue;
        }

        if !open && raw.starts_with("--- ") {
            if raw.contains("/dev/null") {
                f.old_path = None;
                f.is_new = true;
            } else {
                f.old_path = Some(strip(&raw[4..]));
            }
            continue;
        }
        if !open && raw.starts_with("+++ ") {
            if raw.contains("/dev/null") {
                f.new_path = None;
                f.is_deleted = true;
            } else {
                f.new_path = Some(strip(&raw[4..]));
            }
            continue;
        }

        if !open {
            if let Some(m) = HUNK_RE.captures(raw) {
                hunk = Some(Hunk {
                    old_start: m[1].parse().unwrap_or(1),
                    new_start: m[3].parse().unwrap_or(1),
                    old_left: m.get(2).map_or(1, |g| g.as_str().parse().unwrap_or(1)),
                    new_left: m.get(4).map_or(1, |g| g.as_str().parse().unwrap_or(1)),
                    old_count: 0,
                    new_count: 0,
                });
            }
            continue;
        }

        let h = hunk.as_mut().unwrap();
        if raw.starts_with('\\') {
            continue;
        }
        if let Some(rest) = raw.strip_prefix('+') {
            let line = h.new_start + h.new_count;
            h.new_count += 1;
            h.new_left -= 1;
            f.adds.push(DiffLine {
                text: rest.to_string(),
                line,
            });
        } else if let Some(rest) = raw.strip_prefix('-') {
            let line = h.old_start + h.old_count;
            h.old_count += 1;
            h.old_left -= 1;
            f.dels.push(DiffLine {
                text: rest.to_string(),
                line,
            });
        } else {
            let text = raw.strip_prefix(' ').unwrap_or(raw);
            let line = h.new_start + h.new_count;
            h.new_count += 1;
            h.old_count += 1;
            h.old_left -= 1;
            h.new_left -= 1;
            f.ctxs.push(DiffLine {
                text: text.to_string(),
                line,
            });
        }
    }

    files
}

/// Paths nobody should lint: lockfiles, build output, minified, snapshots.
pub static GENERATED_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|composer\.lock|Cargo\.lock|poetry\.lock|Gemfile\.lock|go\.sum)|\.min\.[a-z]+$|(^|/)dist/|(^|/)build/|\.snap$|\.map$")
        .unwrap()
});

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Totals {
    pub files: usize,
    pub add: usize,
    pub del: usize,
}

pub fn totals(files: &[FileDiff]) -> Totals {
    Totals {
        files: files.len(),
        add: files.iter().map(|f| f.adds.len()).sum(),
        del: files.iter().map(|f| f.dels.len()).sum(),
    }
}
