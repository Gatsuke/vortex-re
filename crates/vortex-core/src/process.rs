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
//! clock ticks since boot); on Windows the creation time reported by
//! `GetProcessTimes` serves the same role. In both cases, if we recorded
//! it, a mismatch means the pid now belongs to a *different* process, so
//! the original owner is dead. Where the start time is unavailable the
//! check degrades to plain liveness and says so — never a guess presented
//! as a fact.
//!
//! Windows needs one extra step: a terminated process whose object is
//! still referenced (a parent holding a `Child` handle, for example) can
//! still be opened, so a live handle alone proves nothing. The exit time
//! (`GetProcessTimes`) and the exit code (`GetExitCodeProcess`, where
//! `STILL_ACTIVE` means not exited) close that gap; a process that exited
//! with the literal code 259 would be misreported as alive — documented
//! here rather than hidden behind a heuristic.

/// Identity of the process that owns (or owned) a run record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    /// Operating-system process id.
    pub pid: u32,
    /// Process start time, when it could be recorded: clock ticks since
    /// boot (Linux `/proc/<pid>/stat` field 22) or the process creation
    /// time as a Windows `FILETIME` u64. `None` means the reuse defense is
    /// unavailable on this platform.
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
    #[cfg(windows)]
    {
        windows_owner_is_alive(info)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = info;
        None
    }
}

#[cfg(windows)]
fn windows_owner_is_alive(info: &ProcessInfo) -> Option<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// `STILL_ACTIVE` from processthreadsapi.h (259): the exit code a live
    /// process reports. Not exposed by windows-sys, so declared here.
    const STILL_ACTIVE: u32 = 259;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, info.pid) };
    if handle.is_null() {
        // No handle: the pid is either not in use at all, or exists but is
        // not ours to query — the Windows analogue of ESRCH and EPERM.
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(code)
                if code == windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER as i32 =>
            {
                Some(false)
            }
            Some(code) if code == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32 => {
                Some(true)
            }
            _ => None, // unexpected failure; do not guess
        };
    }

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut _kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut _user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit_code: u32 = 0;
    let times_ok = unsafe {
        GetProcessTimes(
            handle,
            &mut creation,
            &mut exit_time,
            &mut _kernel,
            &mut _user,
        )
    };
    let code_ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    unsafe { CloseHandle(handle) };
    if times_ok == 0 || code_ok == 0 {
        return None; // could not query; do not guess
    }

    // A live process reports STILL_ACTIVE and has no exit time written.
    // Either signal of exit is conclusive; requiring both would resurrect
    // processes that exited with code 259 or hand out handles with stale
    // exit-time buffers.
    let exited =
        exit_code != STILL_ACTIVE || exit_time.dwLowDateTime != 0 || exit_time.dwHighDateTime != 0;
    if exited {
        return Some(false);
    }

    // Alive (or at least present). Refuse to trust the pid when the
    // recorded creation time no longer matches — the pid was reused.
    if let Some(recorded_start) = info.proc_start {
        let current_start =
            (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        if current_start != recorded_start {
            return Some(false); // pid reused; original owner is gone
        }
    }
    Some(true)
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

/// Read the process creation time as a `FILETIME` u64 via `OpenProcess` +
/// `GetProcessTimes`. Returns `None` when the process cannot be opened or
/// queried (including when it has already exited).
#[cfg(windows)]
fn proc_start_of(pid: u32) -> Option<u64> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut _exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut _kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut _user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let ok =
        unsafe { GetProcessTimes(handle, &mut creation, &mut _exit, &mut _kernel, &mut _user) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return None;
    }
    Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

#[cfg(not(any(unix, windows)))]
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
            #[cfg(windows)]
            let pid: u32 = {
                // `cmd /C exit 0` exits immediately; by the time wait()
                // returns the process has terminated (the exit-time /
                // exit-code path is exactly what the probe must catch,
                // because the test harness still holds its handle).
                let mut child = Command::new("cmd")
                    .args(["/C", "exit 0"])
                    .spawn()
                    .expect("spawn cmd");
                let pid = child.id();
                let _ = child.wait().expect("wait for cmd");
                pid
            };
            #[cfg(not(any(unix, windows)))]
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

    #[cfg(windows)]
    #[test]
    fn proc_start_is_recorded_on_windows() {
        let me = current();
        assert!(
            me.proc_start.is_some(),
            "Windows must record process creation times"
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
