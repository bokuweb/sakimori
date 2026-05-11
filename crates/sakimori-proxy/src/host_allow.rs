//! Hostname allow-list for the proxy's egress filter.
//!
//! Closes the gap that the eBPF supervisor leaves on its own — the
//! kernel layer can only enforce by resolved IP, which loses against
//! CDN rotation. Doing the check at the proxy's CONNECT layer gives
//! us FQDN/wildcard semantics that match what `step-security/harden-runner`
//! users expect (`api.github.com:443`, `*.githubusercontent.com:443`).
//!
//! Pattern grammar:
//!
//! - `host.example.com` — exact match (case-insensitive).
//! - `*.example.com` — any direct or transitive subdomain
//!   (`a.example.com`, `a.b.example.com`, …). Does **not** match the
//!   bare apex `example.com`; add a separate entry for that. The
//!   leading `*.` is the only wildcard form supported — embedded
//!   `*` characters return a parse error rather than silently
//!   matching nothing.
//! - Port suffix on a query (`example.com:443`) is stripped before
//!   matching; patterns describe hosts, not (host, port) pairs.
//!   The proxy applies a separate per-port check elsewhere if
//!   needed.
//!
//! Match semantics:
//!
//! - Empty list → no policy configured → caller treats every host
//!   as allowed (current pre-policy behaviour).
//! - Non-empty list → default-deny, allow only what's listed.
//!   That's the point of the feature; an "allow plus default-allow"
//!   list reduces to "no policy".

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    /// Exact host (already lower-cased at parse).
    Exact(String),
    /// `*.<suffix>` — matches `*.suffix` where the host strictly ends
    /// in `.suffix` (suffix stored without the leading dot).
    SubdomainOf(String),
}

#[derive(Debug, Clone, Default)]
pub struct HostMatcher {
    patterns: Vec<Pattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    /// `*` appears anywhere other than as a leading `*.` prefix.
    BadWildcard,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty hostname pattern"),
            Self::BadWildcard => write!(
                f,
                "only a leading `*.` wildcard is supported (e.g. `*.example.com`)"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

impl HostMatcher {
    /// Build from an iterator of patterns. Returns the first parse
    /// error encountered, with the offending input attached so the
    /// CLI can point at the bad line. Order is preserved — useful
    /// for any future "first match wins" semantics, though the
    /// current implementation is order-independent.
    pub fn from_patterns<I, S>(patterns: I) -> Result<Self, (String, ParseError)>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = Vec::new();
        for raw in patterns {
            let s = raw.as_ref().trim();
            if s.is_empty() {
                continue;
            }
            let parsed = parse_pattern(s).map_err(|e| (s.to_string(), e))?;
            out.push(parsed);
        }
        Ok(Self { patterns: out })
    }

    /// `true` when no patterns were configured. The caller uses this
    /// to short-circuit: an empty matcher means "feature disabled",
    /// not "deny everything".
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Number of configured patterns. Only used for log formatting
    /// — semantic decisions go through [`Self::is_empty`] or
    /// [`Self::allows`].
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Test a host. Strips a `:port` suffix if present so callers
    /// can pass raw `Host:` headers / CONNECT URI authorities
    /// without pre-processing. `host` is matched case-insensitively
    /// against patterns (which were already lower-cased at parse).
    pub fn allows(&self, host: &str) -> bool {
        if self.patterns.is_empty() {
            // No policy → caller handles via `is_empty()`. Returning
            // `true` here keeps the predicate honest if someone
            // skips the empty check by mistake.
            return true;
        }
        let host = strip_port(host).to_ascii_lowercase();
        self.patterns.iter().any(|p| match p {
            Pattern::Exact(h) => *h == host,
            Pattern::SubdomainOf(suffix) => {
                // `host == suffix` is intentionally NOT a match; the
                // wildcard `*.example.com` excludes the apex.
                host.len() > suffix.len() + 1
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            }
        })
    }
}

fn parse_pattern(input: &str) -> Result<Pattern, ParseError> {
    if input.is_empty() {
        return Err(ParseError::Empty);
    }
    let lower = input.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("*.") {
        if rest.is_empty() || rest.contains('*') {
            return Err(ParseError::BadWildcard);
        }
        Ok(Pattern::SubdomainOf(rest.to_string()))
    } else if lower.contains('*') {
        Err(ParseError::BadWildcard)
    } else {
        Ok(Pattern::Exact(lower))
    }
}

fn strip_port(host: &str) -> &str {
    // IPv6 literals come wrapped in brackets (`[::1]:8080`); strip
    // those down to the inner address. Plain IPv4 / hostname use
    // the last `:`. A bare IPv6 (no brackets, two or more colons)
    // is unambiguous-as-host-only — port specifiers on bare v6
    // literals aren't legal anyway, so we leave them alone rather
    // than risk lopping off the trailing group.
    let bytes = host.as_bytes();
    if bytes.first() == Some(&b'[')
        && let Some(end) = host.find(']')
    {
        return &host[1..end];
    }
    if host.bytes().filter(|b| *b == b':').count() >= 2 {
        return host;
    }
    match host.rfind(':') {
        Some(i) if !host[..i].is_empty() => &host[..i],
        _ => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(pats: &[&str]) -> HostMatcher {
        HostMatcher::from_patterns(pats.iter().copied()).unwrap()
    }

    #[test]
    fn empty_matcher_short_circuits() {
        let m = HostMatcher::default();
        assert!(m.is_empty());
        // The `allows` predicate should still return true for
        // safety even though callers are expected to check
        // `is_empty` first.
        assert!(m.allows("anything.example.com"));
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        let m = mk(&["api.github.com"]);
        assert!(m.allows("api.github.com"));
        assert!(m.allows("API.GitHub.com"));
        assert!(!m.allows("evil.example.com"));
    }

    #[test]
    fn port_is_stripped_before_match() {
        let m = mk(&["api.github.com"]);
        assert!(m.allows("api.github.com:443"));
        assert!(m.allows("api.github.com:8080"));
        assert!(!m.allows("evil.example.com:443"));
    }

    #[test]
    fn ipv6_literal_with_port_is_handled() {
        let m = mk(&["::1"]);
        assert!(m.allows("[::1]:8080"));
        // Bare IPv6 (no brackets, no port) — caller responsibility,
        // we accept as-is.
        assert!(m.allows("::1"));
    }

    #[test]
    fn wildcard_matches_any_subdomain() {
        let m = mk(&["*.githubusercontent.com"]);
        assert!(m.allows("avatars.githubusercontent.com"));
        assert!(m.allows("camo.githubusercontent.com"));
        assert!(m.allows("a.b.c.githubusercontent.com"));
    }

    #[test]
    fn wildcard_does_not_match_apex() {
        // `*.example.com` should NOT match the bare `example.com`.
        // If the user wants both, they list both.
        let m = mk(&["*.example.com"]);
        assert!(!m.allows("example.com"));
        assert!(m.allows("a.example.com"));
    }

    #[test]
    fn wildcard_does_not_match_unrelated_suffix_collision() {
        // `*.example.com` must not match `notexample.com` or
        // `example.com.attacker.com` (both would be true if we just
        // did `ends_with`).
        let m = mk(&["*.example.com"]);
        assert!(!m.allows("notexample.com"));
        assert!(!m.allows("example.com.attacker.com"));
    }

    #[test]
    fn multiple_patterns_or_together() {
        let m = mk(&["api.github.com", "*.githubusercontent.com"]);
        assert!(m.allows("api.github.com"));
        assert!(m.allows("avatars.githubusercontent.com"));
        assert!(!m.allows("registry.npmjs.org"));
    }

    #[test]
    fn empty_lines_in_input_are_skipped() {
        let m = HostMatcher::from_patterns(["api.github.com", "", "  "]).unwrap();
        assert_eq!(m.patterns.len(), 1);
    }

    #[test]
    fn embedded_wildcard_is_rejected() {
        let err = HostMatcher::from_patterns(["api.*.github.com"]).unwrap_err();
        assert_eq!(err.0, "api.*.github.com");
        assert_eq!(err.1, ParseError::BadWildcard);

        let err = HostMatcher::from_patterns(["foo*.bar"]).unwrap_err();
        assert_eq!(err.1, ParseError::BadWildcard);

        // Bare `*` and `*.` (no suffix) also rejected.
        assert_eq!(
            HostMatcher::from_patterns(["*"]).unwrap_err().1,
            ParseError::BadWildcard
        );
        assert_eq!(
            HostMatcher::from_patterns(["*."]).unwrap_err().1,
            ParseError::BadWildcard
        );
    }

    #[test]
    fn parse_lowercases_the_pattern_so_match_doesnt_have_to() {
        let m = mk(&["API.GITHUB.com"]);
        // Internally stored lower-case.
        assert!(matches!(&m.patterns[0], Pattern::Exact(s) if s == "api.github.com"));
        assert!(m.allows("api.github.com"));
    }

    #[test]
    fn strip_port_handles_no_port_no_brackets() {
        assert_eq!(strip_port("example.com"), "example.com");
        assert_eq!(strip_port("example.com:443"), "example.com");
        assert_eq!(strip_port(":443"), ":443"); // empty host, leave alone
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("[2001:db8::1]:443"), "2001:db8::1");
    }
}
