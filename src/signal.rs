// Windows: Ctrl-C handling is done via the console control handler installed at
// startup in `tui`; there is no POSIX sigaction. Keep the same public API as a
// no-op so callers compile unchanged.
#[cfg(not(target_os = "linux"))]
pub fn ignore() {}

#[cfg(target_os = "linux")]
use libc::sighandler_t;

#[cfg(target_os = "linux")]
pub fn ignore() {
    unsafe {
        let sa = libc::sigaction {
            sa_sigaction: libc::SIG_IGN as sighandler_t,
            sa_mask: std::mem::zeroed(),
            sa_flags: 0,
            sa_restorer: None,
        };
        for sig in [
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGQUIT,
            libc::SIGTSTP,
        ] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}
