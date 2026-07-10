use anyhow::{Context, Result, anyhow};
use std::ffi::OsStr;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;

pub(crate) fn notify_ready(notify_socket: Option<&OsStr>, status: &str) -> Result<()> {
    let Some(notify_socket) = notify_socket else {
        return Ok(());
    };
    let address = notify_address(notify_socket)?;
    let socket = UnixDatagram::unbound().context("creating systemd notification socket")?;
    let message = format!("READY=1\nSTATUS={status}");
    let sent = socket
        .send_to_addr(message.as_bytes(), &address)
        .context("sending systemd readiness notification")?;
    if sent != message.len() {
        return Err(anyhow!(
            "short systemd readiness notification: sent {sent} of {} bytes",
            message.len()
        ));
    }

    Ok(())
}

fn notify_address(notify_socket: &OsStr) -> Result<SocketAddr> {
    let bytes = notify_socket.as_bytes();
    if let Some(abstract_name) = bytes.strip_prefix(b"@") {
        return SocketAddr::from_abstract_name(abstract_name)
            .context("parsing abstract systemd notification socket");
    }

    SocketAddr::from_pathname(Path::new(notify_socket))
        .context("parsing systemd notification socket path")
}

#[cfg(test)]
mod tests {
    use super::notify_ready;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::net::UnixDatagram;
    use std::time::Duration;

    #[test]
    fn ready_notification_contains_ready_and_status() {
        let socket_path =
            std::env::temp_dir().join(format!("config-guard-notify-{}", std::process::id()));
        let _ = fs::remove_file(&socket_path);
        let receiver = UnixDatagram::bind(&socket_path).expect("bind notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set notify timeout");

        notify_ready(Some(OsStr::new(&socket_path)), "watching test")
            .expect("send ready notification");

        let mut message = [0u8; 128];
        let received = receiver
            .recv(&mut message)
            .expect("receive ready notification");
        let message = std::str::from_utf8(&message[..received]).expect("ready message utf8");
        assert_eq!(message, "READY=1\nSTATUS=watching test");
        let _ = fs::remove_file(socket_path);
    }
}
