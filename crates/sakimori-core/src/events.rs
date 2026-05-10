//! Event enum shared between Linux eBPF decoder and Windows ETW parser.

use crate::attribution::Attribution;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    Exec {
        #[serde(default)]
        pid: u32,
        #[serde(default)]
        uid: u32,
        #[serde(default)]
        comm: String,
        #[serde(default)]
        filename: String,
        #[serde(default)]
        argv0: String,
        #[serde(default)]
        denied: bool,
        /// PPid-chain attribution attached by the userspace
        /// supervisor — names the package manager (if any) that
        /// ultimately spawned this exec. See [`crate::attribution`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<Attribution>,
    },
    Connect {
        #[serde(default)]
        pid: u32,
        #[serde(default)]
        uid: u32,
        #[serde(default)]
        comm: String,
        #[serde(default)]
        daddr: String,
        #[serde(default)]
        dport: u16,
        #[serde(default)]
        protocol: u16,
        #[serde(default)]
        denied: bool,
        /// Reverse-DNS of `daddr` (PTR record) when known. Populated
        /// best-effort by the userspace supervisor after all events
        /// are collected — the kernel decoder doesn't know it.
        /// `None` means either "lookup not attempted" or "no PTR".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<Attribution>,
    },
    Open {
        #[serde(default)]
        pid: u32,
        #[serde(default)]
        uid: u32,
        #[serde(default)]
        comm: String,
        #[serde(default)]
        filename: String,
        #[serde(default)]
        flags: u32,
        #[serde(default)]
        denied: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source: Option<Attribution>,
    },
}

impl Event {
    pub fn denied(&self) -> bool {
        match self {
            Event::Exec { denied, .. }
            | Event::Connect { denied, .. }
            | Event::Open { denied, .. } => *denied,
        }
    }

    /// Compact discriminant used to bucket events by kind for sampling.
    pub fn kind_tag(&self) -> u8 {
        match self {
            Event::Exec { .. } => 0,
            Event::Connect { .. } => 1,
            Event::Open { .. } => 2,
        }
    }

    /// Read access to the originating pid — every variant has one.
    pub fn pid(&self) -> u32 {
        match self {
            Event::Exec { pid, .. } | Event::Connect { pid, .. } | Event::Open { pid, .. } => *pid,
        }
    }

    /// Replace the source-attribution slot. Lets the supervisor's
    /// drain task enrich an event after decode without reaching into
    /// the variant fields.
    pub fn set_source(&mut self, src: Option<Attribution>) {
        match self {
            Event::Exec { source, .. }
            | Event::Connect { source, .. }
            | Event::Open { source, .. } => *source = src,
        }
    }

    /// Read the source attribution if one was attached.
    pub fn source(&self) -> Option<&Attribution> {
        match self {
            Event::Exec { source, .. }
            | Event::Connect { source, .. }
            | Event::Open { source, .. } => source.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_and_kind_tag_variant_mapping() {
        let exec = Event::Exec {
            pid: 1,
            uid: 0,
            comm: "".into(),
            filename: "".into(),
            argv0: "".into(),
            denied: true,
            source: None,
        };
        let connect = Event::Connect {
            pid: 1,
            uid: 0,
            comm: "".into(),
            daddr: "".into(),
            dport: 0,
            protocol: 6,
            denied: false,
            hostname: None,
            source: None,
        };
        let open = Event::Open {
            pid: 1,
            uid: 0,
            comm: "".into(),
            filename: "".into(),
            flags: 0,
            denied: true,
            source: None,
        };
        assert_eq!(exec.kind_tag(), 0);
        assert_eq!(connect.kind_tag(), 1);
        assert_eq!(open.kind_tag(), 2);
        assert!(exec.denied());
        assert!(!connect.denied());
        assert!(open.denied());
    }

    #[test]
    fn serialises_tag_field_as_snake_case() {
        let e = Event::Exec {
            pid: 1,
            uid: 2,
            comm: "cmd".into(),
            filename: "/x".into(),
            argv0: "x".into(),
            denied: false,
            source: None,
        };
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["kind"], "exec");
        let o = Event::Open {
            pid: 1,
            uid: 2,
            comm: "".into(),
            filename: "/x".into(),
            flags: 0,
            denied: false,
            source: None,
        };
        assert_eq!(serde_json::to_value(&o).unwrap()["kind"], "open");
    }
}
