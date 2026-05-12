use crate::transport::resumption::SessionTicket;
use std::path::PathBuf;

fn ticket_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("seam")
        .join("tickets")
}

fn ticket_path(host: &str) -> PathBuf {
    ticket_dir().join(format!("{host}.ticket"))
}

/// Load a saved session ticket for `host`, if any.
pub fn load_ticket(host: &str) -> Option<SessionTicket> {
    let path = ticket_path(host);
    let bytes = std::fs::read(path).ok()?;
    SessionTicket::from_bytes(&bytes)
}

/// Save a session ticket for `host`.
pub fn save_ticket(host: &str, ticket: &SessionTicket) -> std::io::Result<()> {
    let dir = ticket_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(ticket_path(host), ticket.to_bytes())
}

/// Delete any saved ticket for `host`.
pub fn delete_ticket(host: &str) {
    let _ = std::fs::remove_file(ticket_path(host));
}
