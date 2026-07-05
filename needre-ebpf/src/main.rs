#![no_std]
#![no_main]
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
};

use needre_common::{EventType, ProcessEvent};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024*1024, 0);

// ---- execve: records the binary a process executes ------------------------

#[tracepoint]
pub fn needre(ctx: TracePointContext) -> u32 {
    match try_needre(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_needre(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xFFFFFFFF) as u32;
    let tgid = (pid_tgid >> 32) as u32;
    let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    let comm = bpf_get_current_comm().map_err(|e| e)?;
    // sys_enter_execve tracepoint layout: filename ptr at offset 16
    let filename_ptr = unsafe { ctx.read_at::<u64>(16) }? as *const u8;

    let mut buf = EVENTS.reserve::<ProcessEvent>(0).ok_or(1i64)?;
    let raw = buf.as_mut_ptr();
    unsafe {
        (*raw).event_type = EventType::Exec;
        (*raw).pid = pid;
        (*raw).tgid = tgid;
        // The parent is resolved in userspace from the process tree built by
        // the fork hook, so we leave it unset here.
        (*raw).parent_pid = 0;
        (*raw).uid = uid;
        (*raw).comm = comm;
        let filename_bytes = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*raw).filename)
            .unwrap_or(&[]);
        (*raw).filename_len = filename_bytes.len() as u32;
    }
    buf.submit(0);
    Ok(0)
}

// ---- fork: records the parent/child relationship of every new process -----

#[tracepoint]
pub fn needre_fork(ctx: TracePointContext) -> u32 {
    match try_fork(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_fork(ctx: TracePointContext) -> Result<u32, i64> {
    // sched_process_fork tracepoint layout (this kernel):
    //   offset 12: pid_t parent_pid
    //   offset 16: __data_loc child_comm  (u32: low 16 bits = offset, high 16 = len)
    //   offset 20: pid_t child_pid
    let parent_pid = unsafe { ctx.read_at::<i32>(12) }? as u32;
    let child_pid = unsafe { ctx.read_at::<i32>(20) }? as u32;
    // Fork runs in the parent's context, so the child inherits the parent's uid.
    let uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;

    // Decode the __data_loc for child_comm to find where the string lives.
    let comm_dataloc = unsafe { ctx.read_at::<u32>(16) }?;
    let comm_off = (comm_dataloc & 0xFFFF) as usize;
    let child_comm = unsafe { ctx.read_at::<[u8; 16]>(comm_off) }.unwrap_or([0u8; 16]);

    let mut buf = EVENTS.reserve::<ProcessEvent>(0).ok_or(1i64)?;
    let raw = buf.as_mut_ptr();
    unsafe {
        (*raw).event_type = EventType::Fork;
        // A freshly forked process is its own thread group leader: pid == tgid.
        (*raw).pid = child_pid;
        (*raw).tgid = child_pid;
        (*raw).parent_pid = parent_pid;
        (*raw).uid = uid;
        (*raw).comm = child_comm;
        // No binary has been exec'd yet at fork time.
        (*raw).filename = [0u8; 256];
        (*raw).filename_len = 0;
    }
    buf.submit(0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
