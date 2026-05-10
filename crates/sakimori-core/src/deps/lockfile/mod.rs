pub mod cargo;
pub mod npm;
pub mod nuget;
pub mod pypi;

use std::path::Path;

use anyhow::Result;

use super::{Ecosystem, Package};

pub fn detect(path: &Path) -> Result<Ecosystem> {
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    match fname {
        "package-lock.json" => Ok(Ecosystem::Npm),
        "Cargo.lock" => Ok(Ecosystem::Crates),
        "uv.lock" | "poetry.lock" => Ok(Ecosystem::Pypi),
        "requirements.txt" => Ok(Ecosystem::Pypi),
        "packages.lock.json" => Ok(Ecosystem::Nuget),
        _ => anyhow::bail!(
            "unsupported lockfile '{fname}' (supported: package-lock.json, Cargo.lock, \
             uv.lock, poetry.lock, requirements.txt, packages.lock.json)"
        ),
    }
}

pub fn parse(eco: Ecosystem, path: &Path) -> Result<Vec<Package>> {
    match eco {
        Ecosystem::Npm => npm::parse(path),
        Ecosystem::Crates => cargo::parse(path),
        Ecosystem::Pypi => pypi::parse(path),
        Ecosystem::Nuget => nuget::parse(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detect_returns_expected_ecosystem_for_each_filename() {
        assert_eq!(
            detect(&PathBuf::from("some/dir/package-lock.json")).unwrap(),
            Ecosystem::Npm
        );
        assert_eq!(
            detect(&PathBuf::from("Cargo.lock")).unwrap(),
            Ecosystem::Crates
        );
        assert_eq!(detect(&PathBuf::from("uv.lock")).unwrap(), Ecosystem::Pypi);
        assert_eq!(
            detect(&PathBuf::from("poetry.lock")).unwrap(),
            Ecosystem::Pypi
        );
        assert_eq!(
            detect(&PathBuf::from("requirements.txt")).unwrap(),
            Ecosystem::Pypi
        );
        assert_eq!(
            detect(&PathBuf::from("packages.lock.json")).unwrap(),
            Ecosystem::Nuget
        );
    }

    #[test]
    fn detect_rejects_unknown_filenames() {
        assert!(detect(&PathBuf::from("Gemfile.lock")).is_err());
        assert!(detect(&PathBuf::from("go.sum")).is_err());
        assert!(detect(&PathBuf::from("foo.txt")).is_err());
    }
}
