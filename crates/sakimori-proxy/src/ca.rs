//! Root CA lifecycle.
//!
//! On first run we generate a self-signed CA and persist it to
//! `$XDG_CONFIG_HOME/sakimori/` (`%APPDATA%\sakimori` on Windows).
//! Subsequent runs reuse it. The CA is *scoped to this user's
//! sakimori install* — no shared key material, no publicly-trusted
//! trust anchor. The proxy won't function until the user adds the CA
//! to their trust store; we surface the instructions on first run.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

pub struct CaFiles {
    pub dir: PathBuf,
    pub cert_pem: PathBuf,
    pub key_pem: PathBuf,
}

impl CaFiles {
    pub fn at_default_location() -> Result<Self> {
        let dir = default_config_dir()?.join("sakimori");
        Ok(Self::at(dir))
    }

    pub fn at(dir: PathBuf) -> Self {
        let cert_pem = dir.join("ca.pem");
        let key_pem = dir.join("ca.key");
        Self {
            dir,
            cert_pem,
            key_pem,
        }
    }

    pub fn exists(&self) -> bool {
        self.cert_pem.exists() && self.key_pem.exists()
    }
}

/// Load-or-generate the root CA. Returns (cert_pem_bytes, key_pem_bytes)
/// and whether this was a freshly-generated CA (so the caller can print
/// install instructions on the first run).
pub fn ensure_ca(files: &CaFiles) -> Result<(Vec<u8>, Vec<u8>, bool)> {
    if files.exists() {
        let cert = fs::read(&files.cert_pem)
            .with_context(|| format!("reading {}", files.cert_pem.display()))?;
        let key = fs::read(&files.key_pem)
            .with_context(|| format!("reading {}", files.key_pem.display()))?;
        return Ok((cert, key, false));
    }
    fs::create_dir_all(&files.dir).with_context(|| format!("mkdir -p {}", files.dir.display()))?;
    let (cert_pem, key_pem) = generate_ca()?;
    fs::write(&files.cert_pem, &cert_pem)
        .with_context(|| format!("writing {}", files.cert_pem.display()))?;
    fs::write(&files.key_pem, &key_pem)
        .with_context(|| format!("writing {}", files.key_pem.display()))?;
    // Restrict key readability to the owner on unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&files.key_pem)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&files.key_pem, perms)?;
    }
    Ok((cert_pem, key_pem, true))
}

fn generate_ca() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "sakimori proxy root");
    dn.push(DnType::OrganizationName, "sakimori");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    // 10 years — long enough to not annoy the user; they can rotate by
    // deleting the files and rerunning.
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

    let key = KeyPair::generate().context("generating CA keypair")?;
    let cert = params.self_signed(&key).context("self-signing CA")?;
    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
}

fn default_config_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(p));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".config"));
    }
    if let Some(p) = std::env::var_os("APPDATA") {
        return Ok(PathBuf::from(p));
    }
    anyhow::bail!("cannot locate a config dir (no $XDG_CONFIG_HOME / $HOME / %APPDATA%)")
}

/// Render per-OS instructions for trusting the freshly-generated CA.
pub fn trust_instructions(files: &CaFiles) -> String {
    let p = files.cert_pem.display();
    format!(
        "# macOS\nsudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {p}\n\n\
         # Linux (Debian/Ubuntu)\nsudo cp {p} /usr/local/share/ca-certificates/sakimori-ca.crt\n\
         sudo update-ca-certificates\n\n\
         # Windows (admin PowerShell)\nImport-Certificate -FilePath '{p}' -CertStoreLocation Cert:\\LocalMachine\\Root\n",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("sakimori-ca-{tag}-{id}"));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn first_run_generates_and_persists_ca() {
        let d = tmpdir("first");
        let files = CaFiles::at(d.join("sakimori"));
        assert!(!files.exists());

        let (cert, key, generated) = ensure_ca(&files).unwrap();
        assert!(generated);
        assert!(files.exists());
        assert!(!cert.is_empty() && !key.is_empty());
        let cert_str = String::from_utf8_lossy(&cert);
        assert!(cert_str.starts_with("-----BEGIN CERTIFICATE-----"));
        let key_str = String::from_utf8_lossy(&key);
        assert!(key_str.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn second_run_reuses_existing_ca() {
        let d = tmpdir("reuse");
        let files = CaFiles::at(d.join("sakimori"));
        let (cert1, key1, gen1) = ensure_ca(&files).unwrap();
        assert!(gen1);
        let (cert2, key2, gen2) = ensure_ca(&files).unwrap();
        assert!(!gen2);
        assert_eq!(cert1, cert2);
        assert_eq!(key1, key2);
    }

    #[cfg(unix)]
    #[test]
    fn key_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("perms");
        let files = CaFiles::at(d.join("sakimori"));
        ensure_ca(&files).unwrap();
        let mode = fs::metadata(&files.key_pem).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got {:o}", mode & 0o777);
    }

    #[test]
    fn trust_instructions_cover_all_three_os() {
        let d = tmpdir("inst");
        let files = CaFiles::at(d.join("sakimori"));
        let s = trust_instructions(&files);
        assert!(s.contains("macOS"));
        assert!(s.contains("Linux"));
        assert!(s.contains("Windows"));
        assert!(s.contains("ca.pem"));
    }
}
