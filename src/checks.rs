//! Slop-signal checks over a parsed diff. Each returns None (clean) or a
//! `Flag`. Weights sum into the slop score (cap 100), scaled by extra hits so
//! one stray console.log isn't punished like forty.
//! `// slopsieve-ignore` on a line, or `[slopsieve-ignore: id]` in the diff or
//! PR body, suppresses that check.

use crate::parse::{FileDiff, Totals, GENERATED_PATH};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

static TEST_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(tests?|__tests__|spec|e2e|cypress|fixtures)/|\.(test|spec)\.[a-z]+$|(_test|_spec)\.[a-z]+$|test_[\w.]+$")
        .unwrap()
});
static MANIFEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|/)(package\.json|requirements.*\.txt|go\.mod|Cargo\.toml|Gemfile|pom\.xml|build\.gradle(\.kts)?|pyproject\.toml)$")
        .unwrap()
});
static DOC_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.(md|mdx|txt|rst|adoc|markdown)$").unwrap());
static COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(//|/\*|\*|#(?:$|[^!])|<!--|--)").unwrap());

#[derive(Debug, Clone, serde::Serialize)]
pub struct Flag {
    pub id: &'static str,
    pub weight: u32,
    pub title: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

struct Hit {
    evidence: Vec<String>,
    detail: Option<String>,
}

impl Hit {
    fn none() -> Option<Hit> {
        None
    }
    fn evidence(v: Vec<String>) -> Option<Hit> {
        if v.is_empty() {
            None
        } else {
            Some(Hit {
                evidence: v,
                detail: None,
            })
        }
    }
    fn detailed(v: Vec<String>, d: String) -> Option<Hit> {
        if v.is_empty() {
            None
        } else {
            Some(Hit {
                evidence: v,
                detail: Some(d),
            })
        }
    }
}

fn ev(f: &FileDiff, l: &crate::parse::DiffLine) -> String {
    format!("{}:{} {}", f.path(), l.line, l.text.trim().chars().take(80).collect::<String>())
}

fn cap(v: Vec<String>, n: usize) -> Vec<String> {
    v.into_iter().take(n).collect()
}

fn comment_body(t: &str) -> String {
    static LEAD: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*(//+|/\*+|\*+|#+|<!--|--)\s?").unwrap());
    static TAIL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\s*(\*/|-->)\s*$").unwrap());
    TAIL.replace(&LEAD.replace(t, ""), "").to_string()
}

fn looks_like_code(s: &str) -> bool {
    static CODE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"=>|\)\s*\{|[\w)\]]\s*[=!<>]=|[;{}]\s*$|\b(if|for|while|elif|import|from|func|fn|def|class|public|private|return|const|let|var)\b[^.]*[(){}=<>;]")
            .unwrap()
    });
    CODE.is_match(s)
}

pub struct Context<'a> {
    /// Working directory used to resolve relative imports; None disables
    /// filesystem checks (stdin mode).
    pub cwd: Option<&'a Path>,
    /// Optional PR metadata; used by `missing-context` and global suppression.
    pub pr_body: Option<&'a str>,
    /// Check ids disabled on the command line.
    pub disabled: HashSet<String>,
}

fn secret_in_diff(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static PAT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)\b(sk_(live|test)_[0-9a-zA-Z]{16,}|sk-[a-zA-Z0-9_-]{16,}|rk_(live|test)_[0-9a-zA-Z]{16,}|ghp_[a-zA-Z0-9]{20,}|gho_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9a-zA-Z-]{10,}|glpat-[0-9a-zA-Z_-]{15,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|npm_[0-9a-zA-Z]{30,}|hf_[0-9a-zA-Z]{30,})\b|\b(api[_-]?key|secret|token|password|passwd|client[_-]?secret)\s*[:=]\s*["']?[0-9a-zA-Z_\-/.+]{20,}["']?"#)
            .unwrap()
    });
    static REDACT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"(['"]?)([0-9a-zA-Z_\-/.+]{8})[0-9a-zA-Z_\-/.+]{6,}"#).unwrap());
    let mut hits = Vec::new();
    for f in files {
        for l in &f.adds {
            if !COMMENT.is_match(&l.text) && PAT.is_match(&l.text) {
                hits.push(REDACT.replace(&ev(f, l), "$1$2...").to_string());
            }
        }
    }
    Hit::evidence(cap(hits, 4))
}

fn test_weakening(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static SKIP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\.(skip|only)\s*\(|^\s*(xit|xdescribe|xtest|ftest)\s*\(|@Disabled|pytest\.mark\.(skip|xfail)|unittest\.skip|\.todo\s*\(")
            .unwrap()
    });
    static TAUT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"assert(True|Equals)\(\s*(true|1)\s*[,)]|expect\(\s*true\s*\)\.(toBe|toEqual)\(\s*true")
            .unwrap()
    });
    static ASSERT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(assert\w*\s*\(|expect\s*\(|\.should\b|verify\s*\()").unwrap());
    static PARAM: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\.(each|forEach|parametrize)|\bfor\s*\(").unwrap());
    let mut hits = Vec::new();
    for f in files.iter().filter(|f| TEST_PATH.is_match(f.path())) {
        let parameterized = f.adds.iter().any(|l| PARAM.is_match(&l.text));
        for l in &f.adds {
            if SKIP.is_match(&l.text) {
                hits.push(ev(f, l));
            }
            if TAUT.is_match(&l.text) {
                hits.push(format!("{}  <- tautological assertion", ev(f, l)));
            }
        }
        let del = f.dels.iter().filter(|l| ASSERT.is_match(&l.text)).count() as i64;
        let add = f.adds.iter().filter(|l| ASSERT.is_match(&l.text)).count() as i64;
        if !parameterized && del - add >= 3 {
            hits.push(format!(
                "{}: {} more assertion lines removed than added",
                f.path(),
                del - add
            ));
        }
    }
    Hit::evidence(cap(hits, 4))
}

fn debug_leftovers(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static STDOUT_TOOL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(^|/)(bin|scripts?|cli|cmds?|tools?)/|(^|/|\.)cli\.[mc]?[jt]s$").unwrap()
    });
    static PRINT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"console\.(log|debug|warn|error|info)\s*\(|fmt\.Println|System\.out\.println|print\s*\(|puts\s+[a-zA-Z_"'(]|println!\s*\(|dbg!\s*\("#)
            .unwrap()
    });
    static TRAP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\bdebugger\b|pdb\.set_trace|binding\.(pry|irb)|var_dump\s*\(|\bdd\s*\(").unwrap()
    });
    let mut hits = Vec::new();
    for f in files {
        for l in &f.adds {
            if !COMMENT.is_match(&l.text)
                && (TRAP.is_match(&l.text)
                    || (PRINT.is_match(&l.text) && !STDOUT_TOOL.is_match(f.path())))
            {
                hits.push(ev(f, l));
            }
        }
    }
    Hit::evidence(cap(hits, 4))
}

fn test_file_deleted(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    let gone: Vec<&&FileDiff> = files
        .iter()
        .filter(|f| f.is_deleted && TEST_PATH.is_match(f.path()))
        .collect();
    let added = files
        .iter()
        .filter(|f| f.is_new && TEST_PATH.is_match(f.path()))
        .count();
    let has_code = files
        .iter()
        .any(|f| !TEST_PATH.is_match(f.path()) && !f.is_deleted);
    if gone.len() > added && has_code {
        Hit::evidence(cap(
            gone.iter()
                .skip(added)
                .map(|f| format!("{} deleted while non-test files changed", f.path()))
                .collect(),
            4,
        ))
    } else {
        Hit::none()
    }
}

fn phantom_imports(files: &[&FileDiff], _tot: &Totals, ctx: &Context) -> Option<Hit> {
    let cwd = ctx.cwd?;
    static IMPORT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?:from|import|require)\s*\(?\s*["'](\.{1,2}/[^"']+)["']|import\s+["'](\.{1,2}/[^"']+)["']"#)
            .unwrap()
    });
    let diff_paths: HashSet<String> = files.iter().map(|f| f.path().to_string()).collect();
    let mut hits = Vec::new();
    for f in files {
        let mut seen = HashSet::new();
        for l in f.adds.iter().chain(f.ctxs.iter()) {
            let m = IMPORT.captures(&l.text).and_then(|c| {
                c.get(1)
                    .or_else(|| c.get(2))
                    .map(|g| g.as_str().to_string())
            });
            let Some(rel) = m else { continue };
            if !seen.insert(rel.clone()) {
                continue;
            }
            let dir = Path::new(f.path()).parent().unwrap_or_else(|| Path::new(""));
            let base = cwd.join(dir).join(&rel);
            let base_norm = base.to_string_lossy().replace('\\', "/");
            if diff_paths
                .iter()
                .any(|p| base_norm.ends_with(&format!("/{p}")) || base_norm == *p)
            {
                continue;
            }
            let candidates = [
                base.clone(),
                base.with_extension("js"),
                base.with_extension("ts"),
                base.with_extension("mjs"),
                base.with_extension("jsx"),
                base.with_extension("tsx"),
                base.with_extension("py"),
                base.join("index.js"),
                base.join("index.ts"),
            ];
            if !candidates.iter().any(|p| p.exists()) {
                hits.push(format!(
                    "{}:{} imports '{}' - not found on disk or in this diff",
                    f.path(),
                    l.line,
                    rel
                ));
            }
        }
    }
    Hit::evidence(cap(hits, 4))
}

fn empty_catch(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static PAT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\bcatch\s*(\([^)]*\))?\s*\{\s*\}|\bexcept[^:()]*:\s*pass\s*(#.*)?$|rescue\s*(=>\s*\w+\s*)?(end|#.*)?$")
            .unwrap()
    });
    let mut hits = Vec::new();
    for f in files {
        for l in &f.adds {
            if PAT.is_match(&l.text) {
                hits.push(ev(f, l));
            }
        }
    }
    Hit::evidence(cap(hits, 4))
}

fn trivial_dependency(files: &[&FileDiff], tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static TRIVIAL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^(is-odd|is-even|is-number|left-pad|isarray|is-windows|is-positive|is-negative|is-integer|upper-case|lower-case|is-true|is-false)$")
            .unwrap()
    });
    static JS_DEP: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#""([\w@./-]+)"\s*:\s*"[\^~>=*\d]"#).unwrap());
    static PY_DEP: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*([\w.-]+)([=<>!~]=|\s*$)").unwrap());
    static IS_DEP: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#""[\w@./-]+"\s*:\s*"[\^~>=<*\d]|^\s*[\w.-]+\s*[=<>!~]=\s*[\d]"#).unwrap()
    });
    let mut hits = Vec::new();
    for f in files.iter().filter(|f| MANIFEST.is_match(f.path())) {
        for l in &f.adds {
            let name = if f.path().ends_with("package.json") {
                JS_DEP.captures(&l.text).map(|c| c[1].to_string())
            } else if f.path().ends_with(".txt") {
                PY_DEP.captures(&l.text).map(|c| c[1].to_string())
            } else {
                None
            };
            if let Some(name) = name {
                let bare = name.split('/').last().unwrap_or(&name);
                if TRIVIAL.is_match(bare) {
                    hits.push(format!("{}:{} adds '{}'", f.path(), l.line, name));
                }
            }
        }
        if hits.is_empty() && tot.add < 250 {
            let net = f.adds.iter().filter(|l| IS_DEP.is_match(&l.text)).count() as i64
                - f.dels.iter().filter(|l| IS_DEP.is_match(&l.text)).count() as i64;
            if net > 0 {
                hits.push(format!(
                    "{}: {} net new dep entr{} for a {}-line diff",
                    f.path(),
                    net,
                    if net > 1 { "ies" } else { "y" },
                    tot.add
                ));
            }
        }
    }
    Hit::evidence(cap(hits, 4))
}

fn untested_feature(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    let src_add: usize = files
        .iter()
        .filter(|f| {
            !TEST_PATH.is_match(f.path())
                && !MANIFEST.is_match(f.path())
                && !DOC_PATH.is_match(f.path())
        })
        .map(|f| f.adds.len())
        .sum();
    let test_add: usize = files
        .iter()
        .filter(|f| TEST_PATH.is_match(f.path()))
        .map(|f| f.adds.len() + f.dels.len())
        .sum();
    if src_add > 150 && test_add == 0 {
        Hit::evidence(vec![format!(
            "{} lines of implementation added, 0 lines touched in test files",
            src_add
        )])
    } else {
        Hit::none()
    }
}

fn commented_out_code(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static DOC_TAG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^@(param|returns?|type|typedef|example|see|throws|template|description|deprecated)\b")
            .unwrap()
    });
    let mut hits = Vec::new();
    for f in files.iter().filter(|f| !DOC_PATH.is_match(f.path())) {
        for l in &f.adds {
            if !COMMENT.is_match(&l.text) {
                continue;
            }
            let body = comment_body(&l.text);
            if DOC_TAG.is_match(&body) {
                continue;
            }
            if looks_like_code(&body) {
                hits.push(ev(f, l));
            }
        }
    }
    if hits.len() >= 3 {
        Hit::detailed(cap(hits.clone(), 4), format!("{} commented-out lines", hits.len()))
    } else {
        Hit::none()
    }
}

fn boilerplate_comments(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static PAT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(This (function|method|class|variable|module|code|block|line|is|will|returns?|handles?|checks?|initializes?|creates?|defines?|ensures?|validates?|iterates?|loops?|processes?|parses?|converts?|calculates?|helper|section)|Here,? we|Note that|Simply|First,? we|Then,? we|Next,? we|Finally,? we|Now,? we|Initialize|Iterate over|Loop through|Check (if|whether|that)|Ensure that|Make sure|Declare and initialize|The following (code|function|method|block)|Import (the )?necessary)")
            .unwrap()
    });
    let mut hits = Vec::new();
    for f in files.iter().filter(|f| !DOC_PATH.is_match(f.path())) {
        for l in &f.adds {
            if COMMENT.is_match(&l.text) && PAT.is_match(&l.text) {
                hits.push(ev(f, l));
            }
        }
    }
    if hits.len() >= 4 {
        Hit::detailed(
            cap(hits.clone(), 4),
            format!("{} narration comments", hits.len()),
        )
    } else {
        Hit::none()
    }
}

fn dead_code_added(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static EXPORT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"export\s+(?:async\s+)?(?:function|const|class)\s+(\w+)").unwrap()
    });
    let bodies: Vec<&crate::parse::DiffLine> = files
        .iter()
        .flat_map(|f| f.adds.iter().chain(f.ctxs.iter()))
        .collect();
    let mut hits = Vec::new();
    for f in files.iter().filter(|f| f.is_new) {
        for l in &f.adds {
            if l.text.contains("export default") {
                continue;
            }
            let Some(m) = EXPORT.captures(&l.text) else {
                continue;
            };
            let name = &m[1];
            let word = Regex::new(&format!(r"\b{}\b", regex::escape(name))).unwrap();
            let refs = bodies
                .iter()
                .filter(|b| !(b.line == l.line && b.text == l.text) && word.is_match(&b.text))
                .count();
            if refs == 0 {
                hits.push(format!(
                    "{}:{} '{}' is exported but referenced nowhere in this diff",
                    f.path(),
                    l.line,
                    name
                ));
            }
        }
    }
    Hit::evidence(cap(hits, 3))
}

fn whitespace_churn(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    let norm = |ls: &[crate::parse::DiffLine]| -> String {
        ls.iter()
            .map(|l| l.text.split_whitespace().collect::<String>())
            .collect()
    };
    let churn: Vec<String> = files
        .iter()
        .filter(|f| {
            if f.adds.is_empty() || f.adds.len() != f.dels.len() {
                return false;
            }
            let changed = f
                .adds
                .iter()
                .enumerate()
                .any(|(i, a)| Some(&a.text) != f.dels.get(i).map(|d| &d.text));
            changed && norm(&f.adds) == norm(&f.dels)
        })
        .map(|f| {
            format!(
                "{}: {} lines changed, identical after whitespace normalization",
                f.path(),
                f.adds.len() + f.dels.len()
            )
        })
        .collect();
    Hit::evidence(cap(churn, 4))
}

fn giant_diff(_files: &[&FileDiff], tot: &Totals, _ctx: &Context) -> Option<Hit> {
    let mut hits = Vec::new();
    if tot.add > 800 {
        hits.push(format!("{} added lines (threshold 800)", tot.add));
    }
    if tot.files > 15 {
        hits.push(format!("{} files touched (threshold 15)", tot.files));
    }
    Hit::evidence(hits)
}

fn vague_sprawl(files: &[&FileDiff], _tot: &Totals, _ctx: &Context) -> Option<Hit> {
    static NAME: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(^|/)(utils?|helpers?|misc|common|shared|stuff|tools?|funcs?)\.[^/]+$")
            .unwrap()
    });
    let hits: Vec<String> = files
        .iter()
        .filter(|f| f.is_new && NAME.is_match(f.path()))
        .map(|f| format!("{} created (generic name, catch-all destination)", f.path()))
        .collect();
    Hit::evidence(cap(hits, 3))
}

fn missing_context(_files: &[&FileDiff], _tot: &Totals, ctx: &Context) -> Option<Hit> {
    match ctx.pr_body {
        Some(body) if body.trim().len() < 20 => Hit::evidence(vec![
            "PR body under 20 chars; no linked issue or rationale".to_string(),
        ]),
        _ => Hit::none(),
    }
}

type Check = (
    &'static str,
    u32,
    &'static str,
    fn(&[&FileDiff], &Totals, &Context) -> Option<Hit>,
);

const CHECKS: &[Check] = &[
    ("secret-in-diff", 40, "possible secret committed", secret_in_diff),
    ("test-weakening", 30, "test weakening", test_weakening),
    ("debug-leftovers", 25, "debug leftovers", debug_leftovers),
    ("test-file-deleted", 25, "test file deleted", test_file_deleted),
    ("phantom-imports", 20, "import of missing local file", phantom_imports),
    ("empty-catch", 20, "empty catch/except", empty_catch),
    ("trivial-dependency", 20, "dependency added for trivial use", trivial_dependency),
    ("untested-feature", 15, "feature code, zero test changes", untested_feature),
    ("commented-out-code", 15, "commented-out code shipped", commented_out_code),
    ("boilerplate-comments", 10, "narration comments", boilerplate_comments),
    ("dead-code-added", 10, "exported but unreferenced", dead_code_added),
    ("whitespace-churn", 10, "whitespace-only churn", whitespace_churn),
    ("giant-diff", 10, "oversized diff", giant_diff),
    ("vague-sprawl", 5, "vague util sprawl", vague_sprawl),
    ("missing-context", 5, "no linked context", missing_context),
];

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub score: u32,
    pub band: String,
    pub verdict: String,
    pub totals: Totals,
    pub flags: Vec<Flag>,
    #[serde(rename = "cleanIds")]
    pub clean_ids: Vec<String>,
    #[serde(rename = "skippedGen")]
    pub skipped_gen: usize,
    pub suppressed: Vec<String>,
}

/// Inline markers suppress for the file containing them (eslint-disable
/// style); only PR-body `[slopsieve-ignore: id]` suppresses globally.
fn suppressed(files: &[FileDiff], pr_body: Option<&str>) -> (HashSet<String>, HashMap<String, HashSet<String>>, Vec<String>) {
    static INLINE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"slopsieve-ignore(?::\s*([\w-]+(?:\s*,\s*[\w-]+)*))?").unwrap()
    });
    static GLOBAL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\[slopsieve-ignore(?::\s*([\w-]+(?:\s*,\s*[\w-]+)*))?\]").unwrap()
    });
    let mut global = HashSet::new();
    let mut per_file: HashMap<String, HashSet<String>> = HashMap::new();
    let mut list = Vec::new();
    for f in files {
        for l in f.adds.iter().chain(f.ctxs.iter()) {
            if let Some(m) = INLINE.captures(&l.text) {
                let ids = m.get(1).map(|g| g.as_str()).unwrap_or("all");
                let entry = per_file.entry(f.path().to_string()).or_default();
                for id in ids.split(',') {
                    entry.insert(id.trim().to_string());
                }
            }
        }
    }
    if let Some(body) = pr_body {
        for m in GLOBAL.captures_iter(body) {
            let ids = m.get(1).map(|g| g.as_str()).unwrap_or("all");
            for id in ids.split(',') {
                global.insert(id.trim().to_string());
            }
        }
    }
    for id in &global {
        list.push(id.clone());
    }
    for (p, s) in &per_file {
        for id in s {
            list.push(format!("{p}:{id}"));
        }
    }
    (global, per_file, list)
}

pub fn analyze(raw: &[FileDiff], ctx: &Context) -> Report {
    let files: Vec<&FileDiff> = raw
        .iter()
        .filter(|f| !GENERATED_PATH.is_match(f.path()))
        .collect();
    let skipped_gen = raw.len() - files.len();
    let (global, per_file, suppressed_list) = suppressed(raw, ctx.pr_body);
    let tot = Totals {
        files: files.len(),
        add: files.iter().map(|f| f.adds.len()).sum(),
        del: files.iter().map(|f| f.dels.len()).sum(),
    };

    let mut flags: Vec<Flag> = CHECKS
        .iter()
        .filter(|(id, _, _, _)| {
            !global.contains("all") && !global.contains(*id) && !ctx.disabled.contains(*id)
        })
        .filter_map(|(id, weight, title, run)| {
            let visible: Vec<&FileDiff> = files
                .iter()
                .filter(|f| {
                    let off = per_file.get(f.path());
                    !off.map(|s| s.contains("all") || s.contains(*id)).unwrap_or(false)
                })
                .copied()
                .collect();
            run(&visible, &tot, ctx).map(|hit| {
                let extra = (hit.evidence.len().saturating_sub(1) * 2) as u32;
                Flag {
                    id,
                    weight: (weight + extra).min(weight + weight / 2),
                    title,
                    evidence: hit.evidence,
                    detail: hit.detail,
                }
            })
        })
        .collect();
    flags.sort_by(|a, b| b.weight.cmp(&a.weight));

    let score = flags.iter().map(|f| f.weight).sum::<u32>().min(100);
    let (band, verdict) = match score {
        0..=10 => ("LOW", "low slop signal - looks reviewable"),
        11..=35 => ("MEDIUM", "a few flags - worth a real look"),
        36..=70 => ("HIGH", "heavy slop signal - request changes or an explanation"),
        _ => ("ALARM", "strong unreviewed-generation signals - likely reject"),
    };
    let clean_ids: Vec<String> = CHECKS
        .iter()
        .filter(|(id, _, _, _)| !flags.iter().any(|f| f.id == *id))
        .map(|(_, _, t, _)| t.to_string())
        .collect();

    Report {
        score,
        band: band.to_string(),
        verdict: verdict.to_string(),
        totals: tot,
        flags,
        clean_ids,
        skipped_gen,
        suppressed: suppressed_list,
    }
}
