//! Terminal + JSON + GitHub-Actions + SARIF rendering.

use crate::checks::Report;
use regex::Regex;
use std::sync::LazyLock;

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";

pub fn text_report(r: &Report, target: &str, version: &str, color: bool) -> String {
    let (reset, dim, bold, red, yellow, green) = if color {
        (RESET, DIM, BOLD, RED, YELLOW, GREEN)
    } else {
        ("", "", "", "", "", "")
    };
    let band_color = match r.band.as_str() {
        "LOW" => green,
        "MEDIUM" => yellow,
        _ => red,
    };
    let mut lines = Vec::new();
    lines.push(format!("{bold}slopsieve {version}{reset} {dim}· {target} · {}{reset}", chrono_lite()));
    lines.push(format!("{dim}{}{reset}", "═".repeat(56)));
    lines.push(format!("{band_color}{bold}SLOP SCORE: {}/100 - {}{reset}", r.score, r.band));
    let mut meta = format!(
        "{} files · +{} -{} lines",
        r.totals.files, r.totals.add, r.totals.del
    );
    if r.skipped_gen > 0 {
        meta.push_str(&format!(" · {} generated/lockfile skipped", r.skipped_gen));
    }
    if !r.suppressed.is_empty() {
        meta.push_str(&format!(
            " · suppressed: {}",
            r.suppressed.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        ));
        if r.suppressed.len() > 3 {
            meta.push_str(&format!(" +{} more", r.suppressed.len() - 3));
        }
    }
    lines.push(format!("{dim}{meta}{reset}"));
    lines.push(String::new());
    if !r.flags.is_empty() {
        lines.push(format!("{bold}FLAGS{reset}"));
        for f in &r.flags {
            let detail = f.detail.as_deref().map(|d| format!(" ({d})")).unwrap_or_default();
            lines.push(format!("  {red}[{:>2}] {}{}{reset}", f.weight, f.title, detail));
            for e in &f.evidence {
                lines.push(format!("      {dim}{e}{reset}"));
            }
        }
        lines.push(String::new());
    }
    if !r.clean_ids.is_empty() {
        lines.push(format!("{bold}CLEAN{reset}"));
        lines.push(format!("  {green}{}{reset}", r.clean_ids.join(" · ")));
        lines.push(String::new());
    }
    lines.push(format!("{dim}verdict: {}/100 - {}{reset}", r.score, r.verdict));
    lines.join("\n")
}

fn chrono_lite() -> String {
    // UTC date without pulling in chrono: days since epoch -> Y-M-D.
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    // civil-from-days (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!("{y:04}-{m:02}-{d:02}")
}

/// `::warning` annotations pin each flag onto the PR "Files changed" line.
pub fn github_report(r: &Report) -> String {
    static LOC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+?):(\d+)").unwrap());
    let esc_prop = |s: &str| {
        s.replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A")
            .replace(':', "%3A")
            .replace(',', "%2C")
    };
    let esc_data = |s: &str| {
        s.replace('%', "%25")
            .replace('\r', "%0D")
            .replace('\n', "%0A")
    };
    let mut lines = Vec::new();
    for f in &r.flags {
        for e in &f.evidence {
            if let Some(m) = LOC.captures(e) {
                let head = m.get(0).unwrap().as_str();
                let rest = e[head.len()..].trim();
                lines.push(format!(
                    "::warning file={},line={},title={}::{} - {}",
                    esc_prop(&m[1]),
                    &m[2],
                    esc_prop(f.id),
                    esc_data(f.title),
                    esc_data(rest)
                ));
            } else {
                lines.push(format!(
                    "::warning title={}::{} - {}",
                    esc_prop(f.id),
                    esc_data(f.title),
                    esc_data(e)
                ));
            }
        }
    }
    lines.push(format!("::notice title=slopsieve::score {}/100 - {}", r.score, r.band));
    lines.join("\n")
}

pub fn json_report(r: &Report, target: &str, version: &str) -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "tool": "slopsieve",
        "version": version,
        "target": target,
        "score": r.score,
        "band": r.band,
        "verdict": r.verdict,
        "totals": r.totals,
        "flags": r.flags,
        "cleanIds": r.clean_ids,
        "skippedGen": r.skipped_gen,
        "suppressed": r.suppressed,
    }))
    .unwrap_or_default()
}

pub fn sarif_report(r: &Report, target: &str, version: &str) -> String {
    static LOC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+?):(\d+)").unwrap());
    let rules: Vec<_> = r
        .flags
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "shortDescription": { "text": f.title },
                "defaultConfiguration": { "level": if f.weight >= 25 { "error" } else { "warning" } },
                "properties": { "weight": f.weight }
            })
        })
        .collect();
    let mut results = Vec::new();
    for f in &r.flags {
        let level = if f.weight >= 25 { "error" } else { "warning" };
        if f.evidence.is_empty() {
            results.push(serde_json::json!({
                "ruleId": f.id,
                "level": level,
                "message": { "text": f.title },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "diff" } } }]
            }));
            continue;
        }
        for e in &f.evidence {
            let (uri, start_line, snippet) = match LOC.captures(e) {
                Some(m) => (
                    m[1].to_string(),
                    m[2].parse::<u64>().unwrap_or(1).max(1),
                    e[m.get(0).unwrap().as_str().len()..].trim().to_string(),
                ),
                None => ("diff".to_string(), 1, e.clone()),
            };
            let msg = if snippet.is_empty() {
                f.title.to_string()
            } else {
                format!("{} - {}", f.title, snippet)
            };
            results.push(serde_json::json!({
                "ruleId": f.id,
                "level": level,
                "message": { "text": msg },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": start_line }
                    }
                }]
            }));
        }
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "slopsieve",
                    "version": version,
                    "informationUri": "https://github.com/princejain756/slopsieve-rs",
                    "rules": rules
                }
            },
            "properties": {
                "target": target,
                "score": r.score,
                "band": r.band,
                "verdict": r.verdict,
                "totals": r.totals
            },
            "results": results
        }]
    }))
    .unwrap_or_default()
}
