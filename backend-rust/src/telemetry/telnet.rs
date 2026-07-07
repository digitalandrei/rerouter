//! Telnet TCP port-open probe — a SECONDARY, informational reachability signal.
//!
//! A device that accepts a TCP connection on its telnet port is a weak "the box
//! is up" indicator. Reroutes are gated on SSH, not telnet (a reroute pushes
//! config over SSH), so this signal is only displayed, never used to allow or
//! block an action — see [`crate::reroute::reachability`].
//!
//! We check ONLY that the port accepts a connection; we send and parse nothing
//! (no telnet option negotiation), so this never touches the device CLI. Any
//! failure is `false`, never an error and never a panic (doctrine: telemetry /
//! probes must not take the controller down).

use std::time::Duration;

use tokio::net::TcpStream;

/// Short connect budget — the periodic probe runs inside the poll loop and must
/// not hang it on a filtered port.
const TELNET_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// True if `host:port` accepts a TCP connection within the timeout. Refused,
/// filtered, timed-out, or unresolvable hosts are all simply `false`.
pub async fn telnet_open(host: &str, port: u16) -> bool {
    matches!(
        tokio::time::timeout(TELNET_CONNECT_TIMEOUT, TcpStream::connect((host, port))).await,
        Ok(Ok(_stream))
    )
}
