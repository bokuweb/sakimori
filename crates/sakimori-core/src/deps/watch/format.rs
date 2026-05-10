//! Render a `CheckReport` into a pair of `(title, body)` strings suitable
//! for a macOS / GNOME desktop notification. Kept pure so it's trivial
//! to test without actually posting a notification.

use std::path::Path;

use crate::deps::CheckReport;

pub struct Notification {
    pub title: String,
    pub body: String,
}

/// Build a compact notification for `lockfile`'s `report`. Only call
/// this when `report.violations > 0` — the caller decides whether to
/// surface clean runs at all.
pub fn format_violation(lockfile: &Path, report: &CheckReport) -> Notification {
    let short_path = lockfile
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("(lockfile)")
        .to_string();

    let title = format!("sakimori: {} new deps in {}", report.violations, short_path);

    // Body: up to 3 violating packages, "+N more" if there are extras.
    let mut violating: Vec<String> = report
        .packages
        .iter()
        .filter(|p| p.too_new)
        .take(3)
        .map(|p| {
            let age = p
                .age_hours
                .map(|h| format!("{h}h"))
                .unwrap_or_else(|| "?".into());
            format!("• {}/{}@{} ({age} old)", p.ecosystem, p.name, p.version)
        })
        .collect();
    let extra = report.violations.saturating_sub(violating.len());
    if extra > 0 {
        violating.push(format!("+{extra} more"));
    }

    let body = format!(
        "min-age {}h, {} checked\n{}",
        report.min_age_hours,
        report.checked,
        violating.join("\n")
    );

    Notification { title, body }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{CheckReport, PackageReport};
    use std::path::PathBuf;

    fn pkg(eco: &'static str, name: &str, age: i64, too_new: bool) -> PackageReport {
        PackageReport {
            ecosystem: eco,
            name: name.into(),
            version: "1.0.0".into(),
            published: None,
            age_hours: Some(age),
            too_new,
            error: None,
        }
    }

    fn report(packages: Vec<PackageReport>, min_age_hours: i64) -> CheckReport {
        let violations = packages.iter().filter(|p| p.too_new).count();
        CheckReport {
            min_age_hours,
            checked: packages.len(),
            violations,
            errors: 0,
            packages,
        }
    }

    #[test]
    fn title_mentions_lockfile_basename() {
        let lf = PathBuf::from("/home/u/proj/Cargo.lock");
        let r = report(vec![pkg("crates", "badpkg", 1, true)], 168);
        let n = format_violation(&lf, &r);
        assert!(n.title.contains("Cargo.lock"), "got {:?}", n.title);
        assert!(n.title.contains('1'));
    }

    #[test]
    fn body_lists_first_three_then_summarises() {
        let pkgs = vec![
            pkg("npm", "a", 1, true),
            pkg("npm", "b", 2, true),
            pkg("npm", "c", 3, true),
            pkg("npm", "d", 4, true),
            pkg("npm", "e", 5, true),
        ];
        let r = report(pkgs, 168);
        let n = format_violation(&PathBuf::from("package-lock.json"), &r);
        for name in ["npm/a@", "npm/b@", "npm/c@"] {
            assert!(n.body.contains(name), "missing {name} in {:?}", n.body);
        }
        assert!(
            n.body.contains("+2 more"),
            "expected '+2 more' footer, got {:?}",
            n.body
        );
        assert!(!n.body.contains("npm/d@"));
    }

    #[test]
    fn body_omits_extra_footer_when_fewer_than_three() {
        let r = report(vec![pkg("npm", "solo", 5, true)], 168);
        let n = format_violation(&PathBuf::from("package-lock.json"), &r);
        assert!(!n.body.contains("more"));
        assert!(n.body.contains("npm/solo"));
    }

    #[test]
    fn title_handles_path_without_filename_gracefully() {
        let n = format_violation(
            &PathBuf::from("/"),
            &report(vec![pkg("crates", "x", 1, true)], 24),
        );
        assert!(n.title.contains("lockfile"));
    }

    #[test]
    fn body_includes_min_age_and_checked_count() {
        let r = report(vec![pkg("pypi", "X", 1, true)], 168);
        let n = format_violation(&PathBuf::from("uv.lock"), &r);
        assert!(n.body.starts_with("min-age 168h, 1 checked"));
    }
}
