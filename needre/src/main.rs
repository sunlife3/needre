use aya::maps::RingBuf;
use aya::programs::TracePoint;
use chrono::Local;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::Write;

use needre_common::{EventType, ProcessEvent};

use log::{debug, info, warn};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::signal::unix::{SignalKind, signal as unix_signal};

mod config;
use config::Config;

const DETECT_LOG_PATH: &str = "/var/log/needre/needre_detect.log";

/// Per-process state tracked in userspace, populated from kernel events.
#[derive(Debug, Clone, Default)]
struct ProcInfo {
    ppid: u32,
    uid: u32,
    comm: String,
    /// Last binary exec'd by this pid (empty until an execve is seen).
    path: String,
}

/// Walk the process tree from `start` up towards the root, following the
/// parent links recorded from fork events. Returns the chain leaf-first.
fn ancestry(table: &HashMap<u32, ProcInfo>, start: u32) -> Vec<(u32, ProcInfo)> {
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut cur = start;
    loop {
        if !seen.insert(cur) {
            break; // guard against cycles / pid reuse loops
        }
        match table.get(&cur) {
            Some(info) => {
                chain.push((cur, info.clone()));
                if info.ppid == 0 || info.ppid == cur {
                    break;
                }
                cur = info.ppid;
            }
            None => {
                // Ancestor forked before needre started: record the pid only.
                chain.push((cur, ProcInfo::default()));
                break;
            }
        }
    }
    chain
}

/// Render a process-tree chain (leaf-first) into a readable line.
fn format_tree(chain: &[(u32, ProcInfo)]) -> String {
    chain
        .iter()
        .map(|(pid, info)| {
            let what = if !info.path.is_empty() {
                info.path.clone()
            } else if !info.comm.is_empty() {
                info.comm.clone()
            } else {
                "?".to_string()
            };
            format!("pid={pid}({what})")
        })
        .collect::<Vec<_>>()
        .join(" <- ")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = Config::load()?;

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

    // execve hook: records what binary each process runs.
    let execve: &mut TracePoint = ebpf.program_mut("needre").unwrap().try_into()?;
    execve.load()?;
    execve.attach("syscalls", "sys_enter_execve")?;

    // fork hook: records the parent/child relationship of every new process.
    let fork: &mut TracePoint = ebpf.program_mut("needre_fork").unwrap().try_into()?;
    fork.load()?;
    fork.attach("sched", "sched_process_fork")?;

    let ring = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut ring_fd = AsyncFd::new(ring)?;
    let mut sigterm = unix_signal(SignalKind::terminate())?;

    // Process tree / state, keyed by pid, built from the kernel events.
    let mut table: HashMap<u32, ProcInfo> = HashMap::new();

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

                    match event.event_type {
                        EventType::Fork => {
                            debug!("[FORK] pid={} ppid={} uid={} comm=\"{}\"",
                                event.pid, event.parent_pid, event.uid, comm);
                            // Record the parent link for the new child. Keep any
                            // path we may already know for this pid.
                            let entry = table.entry(event.pid).or_default();
                            entry.ppid = event.parent_pid;
                            entry.uid = event.uid;
                            entry.comm = comm;
                        }
                        EventType::Exec => {
                            info!("[EXECVE] pid={} tgid={} uid={} comm=\"{}\" path=\"{}\"",
                                event.pid, event.tgid, event.uid, comm, path);

                            // Update this pid's state, preserving the ppid learned
                            // at fork time (execve does not change the parent).
                            let entry = table.entry(event.pid).or_default();
                            entry.uid = event.uid;
                            entry.comm = comm.clone();
                            entry.path = path.clone();

                            if config.matching_prefix(&path).is_some() {
                                let chain = ancestry(&table, event.pid);
                                let tree = format_tree(&chain);
                                let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
                                writeln!(detect_log,
                                    "{ts} [DETECT] %1000%: executed suspicious process in monitored directory.; tree: {tree}").ok();
                                warn!("[DETECT] %1000%: executed suspicious process in monitored directory.; tree: {tree}");
                            }
                        }
                        EventType::Exit => {
                            table.remove(&event.pid);
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }

    info!("needre shutting down");
    Ok(())
}
