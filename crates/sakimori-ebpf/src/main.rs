//! Kernel-side eBPF programs for sakimori.
//!
//! Compiled with:
//!   cargo +nightly build -Z build-std=core --target bpfel-unknown-none --release
//!
//! Programs:
//!   - `sakimori_execve`   tracepoint:syscalls:sys_enter_execve
//!   - `sakimori_openat`   tracepoint:syscalls:sys_enter_openat
//!   - `sakimori_connect4` cgroup/connect4
//!   - `sakimori_connect6` cgroup/connect6
//!
//! Design notes
//! ------------
//! - We reserve the event directly inside the ring buffer and write into that
//!   memory (no large stack structs). This keeps us well under the 512-byte
//!   eBPF stack limit.
//! - Filename / argv are *not* copied from userspace in this version — doing
//!   that safely requires `bpf_probe_read_user_str` with tight bounds that
//!   vary by kernel. The userspace `comm` is enough to correlate events; full
//!   path capture is a follow-up once the programs load cleanly.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes, bpf_send_signal,
    },
    macros::{cgroup_sock_addr, map, tracepoint},
    maps::{Array, HashMap, RingBuf},
    programs::{SockAddrContext, TracePointContext},
};
use sakimori_common::{
    COMM_LEN, Connect4Event, Connect6Event, EVENT_KIND_CONNECT4, EVENT_KIND_CONNECT6,
    EVENT_KIND_EXEC, EVENT_KIND_OPEN, EventHeader, ExecEvent, FILE_DENY_MAX_ENTRIES,
    FILE_DENY_PREFIX_LEN, FileDenyPrefix, Ipv4Key, Ipv6Key, OpenEvent, POLICY_ALLOW, POLICY_DENY,
    Settings, VERDICT_ALLOW, VERDICT_DENY,
};

/// POSIX signal number for SIGKILL. bpf_send_signal queues this for
/// delivery on syscall return, which kills the offending process before
/// it can consume whatever `openat` would have returned.
const SIGKILL: u32 = 9;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

#[map]
static NET4: HashMap<Ipv4Key, u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

#[map]
static NET6: HashMap<Ipv6Key, u8> = HashMap::with_max_entries(1024, BPF_F_NO_PREALLOC);

/// Small, bounded prefix map for kernel-side file block. Userspace
/// populates this with the first `FILE_DENY_MAX_ENTRIES` entries from
/// `policy.file.deny`; anything beyond falls through to userspace-only
/// tagging.
#[map]
static FILE_DENY_PREFIX: Array<FileDenyPrefix> =
    Array::with_max_entries(FILE_DENY_MAX_ENTRIES, 0);

#[inline(always)]
fn settings() -> Settings {
    unsafe { SETTINGS.get(0) }.copied().unwrap_or(Settings {
        mode: 0,
        net_default: POLICY_ALLOW as u32,
        file_default: POLICY_ALLOW as u32,
        exec_default: POLICY_ALLOW as u32,
    })
}

#[inline(always)]
fn make_header(kind: u32, verdict: u32) -> EventHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let mut comm = [0u8; COMM_LEN];
    if let Ok(c) = bpf_get_current_comm() {
        // bpf_get_current_comm returns exactly 16 bytes.
        let n = if c.len() < COMM_LEN { c.len() } else { COMM_LEN };
        let mut i = 0;
        while i < n {
            comm[i] = c[i];
            i += 1;
        }
    }
    EventHeader {
        kind,
        verdict,
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        _pad: 0,
        comm,
    }
}

// ---------------------------------------------------------------------------
// execve tracepoint — emits a header-only exec event with zeroed filename/argv0
// ---------------------------------------------------------------------------

#[tracepoint]
pub fn sakimori_execve(ctx: TracePointContext) -> u32 {
    // struct trace_event_raw_sys_enter { u64 unused; u64 id; u64 args[6]; }
    // args[0] = filename  (const char*)        at offset 16
    // args[1] = argv      (const char *const*) at offset 24
    let filename_ptr: *const u8 = match unsafe { ctx.read_at::<*const u8>(16) } {
        Ok(p) => p,
        Err(_) => core::ptr::null(),
    };
    let argv_ptr: *const *const u8 = match unsafe { ctx.read_at::<*const *const u8>(24) } {
        Ok(p) => p,
        Err(_) => core::ptr::null(),
    };

    if let Some(mut entry) = EVENTS.reserve::<ExecEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<ExecEvent>());
            (*ptr).header = make_header(EVENT_KIND_EXEC, VERDICT_ALLOW);

            if !filename_ptr.is_null() {
                let buf: &mut [u8] = &mut (*ptr).filename;
                let _ = bpf_probe_read_user_str_bytes(filename_ptr, buf);
            }

            // argv is an array of user pointers; dereference the first slot
            // to get the argv[0] string pointer, then copy the string itself.
            if !argv_ptr.is_null() {
                if let Ok(first) = bpf_probe_read_user::<*const u8>(argv_ptr) {
                    if !first.is_null() {
                        let buf: &mut [u8] = &mut (*ptr).argv0;
                        let _ = bpf_probe_read_user_str_bytes(first, buf);
                    }
                }
            }
        }
        entry.submit(0);
    }
    0
}

// ---------------------------------------------------------------------------
// openat tracepoint — header-only open event
// ---------------------------------------------------------------------------

// File prefix matching happens in *userspace* from the ringbuf events —
// doing it in the tracepoint blew the verifier's complexity budget (1M
// insns) once the scan got unrolled. The kernel program just ships the
// filename; userspace applies the policy and tags verdicts before the
// aggregate log is printed.
#[tracepoint]
pub fn sakimori_openat(ctx: TracePointContext) -> u32 {
    // args[0] = dfd (i32 padded to u64), args[1] = filename, args[2] = flags
    let filename_ptr: *const u8 = match unsafe { ctx.read_at::<*const u8>(24) } {
        Ok(p) => p,
        Err(_) => core::ptr::null(),
    };
    let flags: u32 = unsafe { ctx.read_at::<u32>(32).unwrap_or(0) };

    // Copy the filename to a local bounded buffer for the deny check.
    let mut scratch = [0u8; FILE_DENY_PREFIX_LEN];
    let mut scratch_len: usize = 0;
    if !filename_ptr.is_null() {
        unsafe {
            if let Ok(read) = bpf_probe_read_user_str_bytes(filename_ptr, &mut scratch) {
                scratch_len = read.len();
            }
        }
    }

    let denied = scratch_len > 0 && file_deny_matches(&scratch, scratch_len);
    if denied && settings().mode == 1 {
        // Kill the offending process. bpf_send_signal runs against
        // the current task (which is the one calling openat); SIGKILL
        // gets queued and delivered when the syscall returns.
        let _ = unsafe { bpf_send_signal(SIGKILL) };
    }

    if let Some(mut entry) = EVENTS.reserve::<OpenEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<OpenEvent>());
            (*ptr).header = make_header(
                EVENT_KIND_OPEN,
                if denied { VERDICT_DENY } else { VERDICT_ALLOW },
            );
            (*ptr).flags = flags;
            if !filename_ptr.is_null() {
                let buf: &mut [u8] = &mut (*ptr).filename;
                let _ = bpf_probe_read_user_str_bytes(filename_ptr, buf);
            }
        }
        entry.submit(0);
    }
    0
}

/// Linear scan of the FILE_DENY_PREFIX map. `FILE_DENY_MAX_ENTRIES = 8`
/// keeps the unrolled program well within the verifier's instruction
/// count budget even after in-lining the per-byte compare loop.
#[inline(always)]
fn file_deny_matches(path: &[u8; FILE_DENY_PREFIX_LEN], path_len: usize) -> bool {
    let mut i: u32 = 0;
    let mut hit = false;
    while i < FILE_DENY_MAX_ENTRIES {
        if !hit
            && let Some(slot) = unsafe { FILE_DENY_PREFIX.get(i) }
        {
            let needle = slot.len as usize;
            if needle > 0 && needle <= FILE_DENY_PREFIX_LEN && needle <= path_len {
                let mut mismatch = false;
                let mut j = 0usize;
                while j < FILE_DENY_PREFIX_LEN {
                    if j < needle && path[j] != slot.bytes[j] {
                        mismatch = true;
                    }
                    j += 1;
                }
                if !mismatch {
                    hit = true;
                }
            }
        }
        i += 1;
    }
    hit
}

// ---------------------------------------------------------------------------
// cgroup connect4
// ---------------------------------------------------------------------------

#[cgroup_sock_addr(connect4)]
pub fn sakimori_connect4(ctx: SockAddrContext) -> i32 {
    let sa = ctx.sock_addr as *const aya_ebpf::bindings::bpf_sock_addr;
    let (daddr, dport) = unsafe {
        (
            core::ptr::read_volatile(&(*sa).user_ip4),
            core::ptr::read_volatile(&(*sa).user_port) as u16,
        )
    };
    let verdict = lookup_net4(daddr, dport);

    if let Some(mut entry) = EVENTS.reserve::<Connect4Event>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Connect4Event>());
            (*ptr).header = make_header(
                EVENT_KIND_CONNECT4,
                if verdict == POLICY_DENY {
                    VERDICT_DENY
                } else {
                    VERDICT_ALLOW
                },
            );
            (*ptr).daddr = daddr;
            (*ptr).dport = dport;
        }
        entry.submit(0);
    }

    if settings().mode == 1 && verdict == POLICY_DENY {
        0 // EPERM to the userspace caller
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// cgroup connect6
// ---------------------------------------------------------------------------
//
// We read the 16-byte user_ip6 as four individual u32 loads via
// read_volatile. A compiler-generated 16-byte memcpy from the ctx is
// rejected by the verifier ("dereference of modified ctx ptr"); splitting
// into four fixed-offset word reads keeps each load inside the
// cgroup_sock_addr ctx whitelist.

#[cgroup_sock_addr(connect6)]
pub fn sakimori_connect6(ctx: SockAddrContext) -> i32 {
    let sa = ctx.sock_addr as *const aya_ebpf::bindings::bpf_sock_addr;
    let (w0, w1, w2, w3, dport) = unsafe {
        (
            core::ptr::read_volatile(&(*sa).user_ip6[0]),
            core::ptr::read_volatile(&(*sa).user_ip6[1]),
            core::ptr::read_volatile(&(*sa).user_ip6[2]),
            core::ptr::read_volatile(&(*sa).user_ip6[3]),
            core::ptr::read_volatile(&(*sa).user_port) as u16,
        )
    };

    let mut daddr = [0u8; 16];
    let b0 = w0.to_ne_bytes();
    let b1 = w1.to_ne_bytes();
    let b2 = w2.to_ne_bytes();
    let b3 = w3.to_ne_bytes();
    daddr[0..4].copy_from_slice(&b0);
    daddr[4..8].copy_from_slice(&b1);
    daddr[8..12].copy_from_slice(&b2);
    daddr[12..16].copy_from_slice(&b3);

    let verdict = lookup_net6(&daddr, dport);

    if let Some(mut entry) = EVENTS.reserve::<Connect6Event>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, core::mem::size_of::<Connect6Event>());
            (*ptr).header = make_header(
                EVENT_KIND_CONNECT6,
                if verdict == POLICY_DENY {
                    VERDICT_DENY
                } else {
                    VERDICT_ALLOW
                },
            );
            (*ptr).daddr = daddr;
            (*ptr).dport = dport;
        }
        entry.submit(0);
    }

    if settings().mode == 1 && verdict == POLICY_DENY {
        0
    } else {
        1
    }
}

#[inline(always)]
fn lookup_net4(addr_be: u32, port_be: u16) -> u8 {
    let key = Ipv4Key {
        addr: addr_be,
        port: port_be,
        _pad: 0,
    };
    if let Some(v) = unsafe { NET4.get(&key) } {
        return *v;
    }
    let wildcard = Ipv4Key {
        addr: addr_be,
        port: 0,
        _pad: 0,
    };
    if let Some(v) = unsafe { NET4.get(&wildcard) } {
        return *v;
    }
    settings().net_default as u8
}

#[inline(always)]
fn lookup_net6(addr: &[u8; 16], port_be: u16) -> u8 {
    let key = Ipv6Key {
        addr: *addr,
        port: port_be,
        _pad: [0; 6],
    };
    if let Some(v) = unsafe { NET6.get(&key) } {
        return *v;
    }
    let wildcard = Ipv6Key {
        addr: *addr,
        port: 0,
        _pad: [0; 6],
    };
    if let Some(v) = unsafe { NET6.get(&wildcard) } {
        return *v;
    }
    settings().net_default as u8
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
