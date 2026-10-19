//! Process identity and liveness, used by crash recovery.
//!
//! Recovery needs to answer one question: is the process that wrote a
//! `running` record still alive? Answering it by age alone either recovers
//! too late (a fresh crash waits out the threshold) or too eagerly (a
//! concurrent, legitimately running process gets marked failed). Recording
//! the owning process identity lets recovery be immediate and safe:
//!
//! * a dead owner means the record can be recovered on the next start,
//!   no matter how recently the crash happened;
//! * a living owner means another vortex process may still be working —
//!   the record is left alone.
//!
//! PID reuse is the classic failure mode of pid checks. On Linux the
//! kernel exposes each process's start time (field 22 of `/proc/<pid>/stat`,
//! clock ticks since boot); if we recorded it, a mismatch means the pid now
//! belongs to a *different* process, so the original owner is dead. Where
//! the start time is unavailable the check degrades to plain liveness and
//! says so — never a guess presented as a fact.

/// Identity of the process that owns (or owned) a run record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    /// Operating-system process id.
    pub pid: u32,
    /// Process start time in clock ticks since boot (Linux `/proc`), when
    /// it could be recorded. `None` means the reuse defense is unavailable
    /// on this platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proc_start: Option<u64>,
}

/// The current process's identity, for stamping onto run records.
pub fn current() -> ProcessInfo {
    ProcessInfo {
        pid: std::process::id(),
        proc_start: proc_start_of(std::process::id()),
    }
}

/// Decide whether the process described by `info` is alive right now.
///
/// Returns `None` when liveness cannot be determined on this platform (the
/// caller must fall back to age-based policy and say so). `Some(true)`
/// requires the pid to respond AND, when a start time was recorded and can
/// be read, the start time to match — a mismatch means the pid was reused
/// by a new process and the original owner is dead.
pub fn owner_is_alive(info: &ProcessInfo) -> Option<bool> {
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(info.pid as i32, 0) };
        let exists = if result == 0 {
            true
        } else {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::ESRCH) => false,
                Some(libc::EPERM) => true, // exists, not ours
                _ => return None,          // unexpected failure; do not guess
            }
        };
        if !exists {
            return Some(false);
        }
        // Alive (or at least present). Refuse to trust the pid when the
        // start time we recorded no longer matches.
        if let Some(recorded_start) = info.proc_start {
            if let Some(current_start) = proc_start_of(info.pid) {
                if current_start != recorded_start {
                    return Some(false); // pid reused; original owner is gone
                }
            }
        }
        Some(true)
    }
    #[cfg(not(unix))]
    {
        let _ = info;
        None
    }
}

/// Read field 22 of `/proc/<pid>/stat` (start time in ticks since boot).
///
/// Returns `None` outside Linux or when the entry cannot be parsed. The
/// comm field may contain spaces inside parentheses, so parsing starts
/// after the final `)`.
#[cfg(target_os = "linux")]
fn proc_start_of(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_paren = stat.rfind(')')?;
    let fields: Vec<&str> = stat[after_paren + 1..].split_whitespace().collect();
    // fields[0] is state (field 3 overall); field 22 is index 22 - 3 = 19.
    fields.get(19)?.parse::<u64>().ok()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn proc_start_of(_pid: u32) -> Option<u64> {
    None
}

#[cfg(not(unix))]
fn proc_start_of(_pid: u32) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn current_process_is_alive() {
        let me = current();
        assert!(me.pid > 0);
        match owner_is_alive(&me) {
            Some(true) => {}
            other => panic!("current process must report alive, got {other:?}"),
        }
    }

    #[test]
    fn exited_process_reports_dead() {
        // A shell prints its own pid, execs `true` (same pid), and exits —
        // by the time we read the output that pid is dead. Retry a few
        // times in case of immediate pid reuse.
        for _ in 0..5 {
            #[cfg(unix)]
            let pid: u32 = {
                let out = Command::new("sh")
                    .arg("-c")
                    .arg("echo $$; exec true")
                    .output()
                    .expect("spawn sh");
                let text = String::from_utf8_lossy(&out.stdout);
                text.trim().parse::<u32>().expect("pid")
            };
            #[cfg(not(unix))]
            let pid: u32 = 0;
            if pid == 0 {
                return; // cannot test on this platform
            }
            let info = ProcessInfo {
                pid,
                proc_start: None,
            };
            if owner_is_alive(&info) == Some(true) {
                continue; // reused already; try again
            }
            assert_eq!(
                owner_is_alive(&info),
                Some(false),
                "pid {pid} should be dead"
            );
            return;
        }
        panic!("could not observe a dead pid after 5 attempts (pid reuse too aggressive?)");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_start_is_recorded_on_linux() {
        let me = current();
        assert!(
            me.proc_start.is_some(),
            "Linux must record /proc start times"
        );
    }

    #[test]
    fn proc_start_parses_from_real_stat() {
        // Cross-check the field-22 parser against /proc/self/stat directly.
        #[cfg(target_os = "linux")]
        {
            let self_pid = std::process::id();
            let stat =
                std::fs::read_to_string(format!("/proc/{self_pid}/stat")).expect("self stat");
            let after = stat.rfind(')').expect("paren");
            let fields: Vec<&str> = stat[after + 1..].split_whitespace().collect();
            let expected: u64 = fields[19].parse().expect("field 22 numeric");
            assert_eq!(proc_start_of(self_pid), Some(expected));
        }
    }
}
