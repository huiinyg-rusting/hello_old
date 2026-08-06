use libc::sighandler_t;

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
