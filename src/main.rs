//! slopsieve - score a diff or PR for AI-slop review signals.
//!
//! Usage:
//!   git diff main...HEAD | slopsieve
//!   slopsieve < patch.diff
//!   slopsieve --format json patch.diff
//!   slopsieve --format github patch.diff   # ::warning annotations for Actions
//!   slopsieve --format sarif patch.diff    # SARIF 2.1.0 for code scanning
//!
//! Exit code is the band: 0 LOW, 1 MEDIUM, 2 HIGH, 3 ALARM (or --strict: any
//! non-LOW is exit 1).

use slopsieve::{checks, parse, report};
use checks::Context;
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() -> ! {
    eprintln!(
        "slopsieve {VERSION} - score a diff for AI-slop review signals

USAGE:
    slopsieve [OPTIONS] [DIFF_FILE]

    With no DIFF_FILE (or '-'), reads the diff from stdin.

OPTIONS:
    -f, --format <fmt>   text (default) | json | github | sarif
        --no-color       plain text, no ANSI colors
        --disable <ids>  comma-separated check ids to skip
        --pr-body <s>    PR body text (enables missing-context + body suppressions)
        --strict         exit 1 unless the score band is LOW
    -h, --help           this help
    -V, --version        print version

CHECKS (weight):
    secret-in-diff(40) test-weakening(30) debug-leftovers(25) test-file-deleted(25)
    phantom-imports(20) empty-catch(20) trivial-dependency(20) untested-feature(15)
    commented-out-code(15) boilerplate-comments(10) dead-code-added(10)
    whitespace-churn(10) giant-diff(10) vague-sprawl(5) missing-context(5)"
    );
    std::process::exit(if std::env::args().any(|a| a == "-h" || a == "--help") {
        0
    } else {
        2
    });
}

fn main() -> ExitCode {
    let mut format = "text".to_string();
    let mut no_color = false;
    let mut strict = false;
    let mut disabled: HashSet<String> = HashSet::new();
    let mut pr_body: Option<String> = None;
    let mut file: Option<String> = None;

    let mut args = std::env::args().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-f" | "--format" => format = args.next().unwrap_or_else(|| usage()),
            s if s.starts_with("--format=") => format = s[9..].to_string(),
            "--no-color" => no_color = true,
            "--strict" => strict = true,
            "--disable" => {
                for id in args.next().unwrap_or_else(|| usage()).split(',') {
                    disabled.insert(id.trim().to_string());
                }
            }
            s if s.starts_with("--disable=") => {
                for id in s[10..].split(',') {
                    disabled.insert(id.trim().to_string());
                }
            }
            "--pr-body" => pr_body = Some(args.next().unwrap_or_else(|| usage())),
            s if s.starts_with("--pr-body=") => pr_body = Some(s[10..].to_string()),
            "-h" | "--help" => usage(),
            "-V" | "--version" => {
                println!("slopsieve {VERSION}");
                return ExitCode::SUCCESS;
            }
            "-" => file = None,
            s if s.starts_with('-') => {
                eprintln!("unknown flag: {s}");
                usage();
            }
            s => file = Some(s.to_string()),
        }
    }

    let (text, target) = match &file {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(t) => (t, p.clone()),
            Err(e) => {
                eprintln!("slopsieve: {p}: {e}");
                return ExitCode::from(2);
            }
        },
        None => {
            let mut buf = String::new();
            if std::io::stdin().read_to_string(&mut buf).is_err() {
                eprintln!("slopsieve: failed to read stdin");
                return ExitCode::from(2);
            }
            (buf, "stdin".to_string())
        }
    };

    let files = parse::parse_diff(&text);
    let cwd = file
        .as_deref()
        .and_then(|p| Path::new(p).parent())
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::current_dir().ok());
    let ctx = Context {
        cwd: cwd.as_deref(),
        pr_body: pr_body.as_deref(),
        disabled,
    };
    let r = checks::analyze(&files, &ctx);

    let out = match format.as_str() {
        "text" => report::text_report(&r, &target, VERSION, !no_color),
        "json" => report::json_report(&r, &target, VERSION),
        "github" => report::github_report(&r),
        "sarif" => report::sarif_report(&r, &target, VERSION),
        other => {
            eprintln!("slopsieve: unknown format '{other}'");
            return ExitCode::from(2);
        }
    };
    println!("{out}");

    if strict && r.band != "LOW" {
        return ExitCode::FAILURE;
    }
    ExitCode::from(match r.band.as_str() {
        "LOW" => 0,
        "MEDIUM" => 1,
        "HIGH" => 2,
        _ => 3,
    })
}
