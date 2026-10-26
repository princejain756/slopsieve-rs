use slopsieve::checks::{analyze, Context};
use slopsieve::parse::parse_diff;
use std::collections::HashSet;
use std::path::Path;

fn ctx() -> Context<'static> {
    Context {
        cwd: Some(Path::new(".")),
        pr_body: None,
        disabled: HashSet::new(),
    }
}

fn flag_ids(r: &slopsieve::checks::Report) -> Vec<&'static str> {
    r.flags.iter().map(|f| f.id).collect()
}

#[test]
fn sloppy_diff_scores_high() {
    let files = parse_diff(include_str!("../fixtures/sloppy.diff"));
    let r = analyze(&files, &ctx());
    let ids = flag_ids(&r);
    for expected in [
        "secret-in-diff",
        "test-weakening",
        "debug-leftovers",
        "empty-catch",
        "trivial-dependency",
        "commented-out-code",
    ] {
        assert!(ids.contains(&expected), "missing flag {expected}, got {ids:?}");
    }
    assert!(r.score >= 70, "expected HIGH/ALARM band, got {}", r.score);
}

#[test]
fn secret_value_is_redacted_in_evidence() {
    let files = parse_diff(include_str!("../fixtures/sloppy.diff"));
    let r = analyze(&files, &ctx());
    let flag = r.flags.iter().find(|f| f.id == "secret-in-diff").unwrap();
    assert!(flag.evidence.iter().any(|e| e.contains("sk_live_")));
    assert!(!flag.evidence.iter().any(|e| e.contains("aB3dEf4gH5iJ6kL7mN8o")));
}

#[test]
fn clean_diff_scores_zero() {
    let files = parse_diff(include_str!("../fixtures/clean.diff"));
    let r = analyze(&files, &ctx());
    assert_eq!(r.score, 0, "clean diff flagged: {:?}", flag_ids(&r));
    assert_eq!(r.band, "LOW");
}

#[test]
fn pr_body_suppression_globally_disables_check() {
    let files = parse_diff(include_str!("../fixtures/sloppy.diff"));
    let mut c = ctx();
    c.pr_body = Some("looks fine [slopsieve-ignore: secret-in-diff]");
    let r = analyze(&files, &c);
    assert!(!flag_ids(&r).contains(&"secret-in-diff"));
}

#[test]
fn inline_marker_suppresses_for_that_file_only() {
    let diff = "diff --git a/a.js b/a.js\nindex 1..2 100644\n--- a/a.js\n+++ b/a.js\n@@ -1,2 +1,3 @@\n const x = 1;\n+// slopsieve-ignore: debug-leftovers\n+console.log(\"hi\");\n\ndiff --git a/b.js b/b.js\nindex 1..2 100644\n--- a/b.js\n+++ b/b.js\n@@ -1,2 +1,3 @@\n const y = 2;\n+console.log(\"there\");\n";
    let files = parse_diff(diff);
    let r = analyze(&files, &ctx());
    let flag = r.flags.iter().find(|f| f.id == "debug-leftovers").unwrap();
    assert!(flag.evidence.iter().any(|e| e.contains("b.js")));
    assert!(!flag.evidence.iter().any(|e| e.contains("a.js")));
}

#[test]
fn parser_handles_plain_diff_u_and_dev_null() {
    let diff = "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,2 @@\n+print(1)\n+print(2)\n";
    let files = parse_diff(diff);
    assert_eq!(files.len(), 1);
    assert!(files[0].is_new);
    assert_eq!(files[0].path(), "new.py");
    assert_eq!(files[0].adds.len(), 2);
}

#[test]
fn generated_paths_are_skipped() {
    let diff = "diff --git a/package-lock.json b/package-lock.json\nindex 1..2 100644\n--- a/package-lock.json\n+++ b/package-lock.json\n@@ -1 +1,40 @@\n+\"version\": \"1.0\"\n";
    let files = parse_diff(diff);
    let r = analyze(&files, &ctx());
    assert_eq!(r.skipped_gen, 1);
}
