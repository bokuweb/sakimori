//! Decoding ring-buffer frames produced by the eBPF side into [`Event`].
//! The enum itself lives in `sakimori-core` so Windows shares it.
//!
//! Note: every decode below intentionally reads `header.tgid`, not
//! `header.pid`. The eBPF side splits `bpf_get_current_pid_tgid()`
//! into the kernel's two senses — `header.pid` is the kernel's
//! per-thread `task->pid` (= TID), `header.tgid` is `task->tgid`
//! (= the POSIX process ID, which is what `getpid()` /
//! `std::process::id()` returns). Users who read the audit log
//! expect the latter, and the supervisor-self filter in
//! `loader::ingest` only works against the latter.

use std::net::{Ipv4Addr, Ipv6Addr};

use sakimori_common::{
    Connect4Event, Connect6Event, EVENT_KIND_CONNECT4, EVENT_KIND_CONNECT6, EVENT_KIND_EXEC,
    EVENT_KIND_OPEN, EventHeader, ExecEvent, OpenEvent, VERDICT_DENY,
};
pub use sakimori_core::events::Event;

/// Decode a ring-buffer frame. Returns `None` if the buffer is too short or
/// the tag is unknown (forward-compatibility for future event kinds).
pub fn decode(bytes: &[u8]) -> Option<Event> {
    if bytes.len() < std::mem::size_of::<EventHeader>() {
        return None;
    }
    let kind = u32::from_ne_bytes(bytes[0..4].try_into().ok()?);
    match kind {
        EVENT_KIND_EXEC => decode_exec(bytes),
        EVENT_KIND_CONNECT4 => decode_connect4(bytes),
        EVENT_KIND_CONNECT6 => decode_connect6(bytes),
        EVENT_KIND_OPEN => decode_open(bytes),
        _ => None,
    }
}

fn decode_exec(bytes: &[u8]) -> Option<Event> {
    let ev: ExecEvent = read_pod(bytes)?;
    Some(Event::Exec {
        pid: ev.header.tgid,
        uid: ev.header.uid,
        comm: cstr(&ev.header.comm),
        filename: cstr(&ev.filename),
        argv0: cstr(&ev.argv0),
        denied: ev.header.verdict == VERDICT_DENY,
        source: None,
    })
}

fn decode_connect4(bytes: &[u8]) -> Option<Event> {
    let ev: Connect4Event = read_pod(bytes)?;
    Some(Event::Connect {
        pid: ev.header.tgid,
        uid: ev.header.uid,
        comm: cstr(&ev.header.comm),
        daddr: Ipv4Addr::from(u32::from_be(ev.daddr)).to_string(),
        dport: u16::from_be(ev.dport),
        protocol: ev.protocol,
        denied: ev.header.verdict == VERDICT_DENY,
        hostname: None,
        source: None,
    })
}

fn decode_connect6(bytes: &[u8]) -> Option<Event> {
    let ev: Connect6Event = read_pod(bytes)?;
    Some(Event::Connect {
        pid: ev.header.tgid,
        uid: ev.header.uid,
        comm: cstr(&ev.header.comm),
        daddr: Ipv6Addr::from(ev.daddr).to_string(),
        dport: u16::from_be(ev.dport),
        protocol: ev.protocol,
        denied: ev.header.verdict == VERDICT_DENY,
        hostname: None,
        source: None,
    })
}

fn decode_open(bytes: &[u8]) -> Option<Event> {
    let ev: OpenEvent = read_pod(bytes)?;
    Some(Event::Open {
        pid: ev.header.tgid,
        uid: ev.header.uid,
        comm: cstr(&ev.header.comm),
        filename: cstr(&ev.filename),
        flags: ev.flags,
        denied: ev.header.verdict == VERDICT_DENY,
        source: None,
    })
}

fn read_pod<T: bytemuck::Pod>(bytes: &[u8]) -> Option<T> {
    let size = std::mem::size_of::<T>();
    if bytes.len() < size {
        return None;
    }
    Some(*bytemuck::from_bytes::<T>(&bytes[..size]))
}

fn cstr(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
