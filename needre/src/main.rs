use aya::maps::RingBuf;
use aya::programs::TracePoint;
use chrono::Local;
use std::convert::TryFrom;
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::Write;

use needre_common::ProcessEvent;

use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::signal::unix::{SignalKind, signal as unix_signal};

const SUSPICIOUS_PREFIXES: &[&str] = &["/tmp"];
const DETECT_LOG_PATH: &str = "/var/log/needre/needre_detect.log";

fn suspicious_prefix(path: &str) -> Option<&'static str> {
    SUSPICIOUS_PREFIXES.iter().copied().find(|&p| path.starts_with(p))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    fs::create_dir_all("/var/log/needre")?;
    let mut detect_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DETECT_LOG_PATH)?;

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/needre"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut TracePoint = ebpf.program_mut("needre").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let ring = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut ring_fd = AsyncFd::new(ring)?;
    let mut sigterm = unix_signal(SignalKind::terminate())?;

    info!("needre started");
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            result = ring_fd.readable_mut() => {
                let mut guard = result?;
                while let Some(item) = guard.get_inner_mut().next() {
                    let event = unsafe { &*(item.as_ptr() as *const ProcessEvent) };
                    let comm = CStr::from_bytes_until_nul(&event.comm)
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let path = CStr::from_bytes_until_nul(&event.filename)
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();

                    info!("[EXECVE] pid={} tgid={} uid={} comm=\"{}\" path=\"{}\"",
                        event.pid, event.tgid, event.uid, comm, path);

                    if let Some(prefix) = suspicious_prefix(&path) {
                        let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
                        writeln!(detect_log,
                            "{} [DETECT] execution from {} | pid={} tgid={} uid={} comm=\"{}\" path=\"{}\"",
                            ts, prefix, event.pid, event.tgid, event.uid, comm, path).ok();
                    }
                }
                guard.clear_ready();
            }
        }
    }

    info!("needre shutting down");
    Ok(())
}
