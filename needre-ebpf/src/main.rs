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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";