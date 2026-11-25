use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;

/// Low-latency UDP shred forwarder using AF_PACKET.
///
/// Captures incoming UDP packets on the given interface via AF_PACKET (zero
/// interference with the normal network stack) and forwards the UDP payload
/// to one or more remote destinations. The default use case is capturing a
/// validator's TVU port for fanout; passing `--dst-ip` restricts capture to a
/// specific IPv4 destination (e.g. a DoubleZero Edge multicast group) so the
/// same binary can act as a multicast-to-unicast bridge into an Agave RPC's
/// TVU socket.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// UDP destination port to capture (typically TVU port 8001)
    #[arg(long, alias = "src-port", default_value = "8001")]
    listen_port: u16,

    /// Optional IPv4 destination address to additionally filter on
    /// (e.g. a multicast group). When unset, any IPv4 destination is accepted.
    #[arg(long)]
    dst_ip: Option<Ipv4Addr>,

    /// Destination(s) to forward to (ip:port). Can be specified multiple times.
    #[arg(long = "dest", required = true)]
    destinations: Vec<String>,

    /// Network interface to capture on (e.g. "eth0"). Auto-detected if empty.
    #[arg(long, default_value = "")]
    iface: String,

    /// Port for Prometheus metrics HTTP endpoint
    #[arg(long, default_value = "9400")]
    metrics_port: u16,

    /// Address the Prometheus metrics HTTP endpoint listens on
    #[arg(long, default_value = "127.0.0.1")]
    metrics_bind: IpAddr,
}

// Shared atomic counters for metrics
struct Metrics {
    packets_received: AtomicU64,
    packets_forwarded: AtomicU64,
    packets_dropped: AtomicU64,
    bytes_forwarded: AtomicU64,
    last_packet_ts: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_forwarded: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            bytes_forwarded: AtomicU64::new(0),
            last_packet_ts: AtomicU64::new(0),
        }
    }

    fn render(&self) -> String {
        format!(
            "# HELP shred_fwd_packets_received_total Packets captured from AF_PACKET\n\
             # TYPE shred_fwd_packets_received_total counter\n\
             shred_fwd_packets_received_total {}\n\
             # HELP shred_fwd_packets_forwarded_total Packets successfully sent\n\
             # TYPE shred_fwd_packets_forwarded_total counter\n\
             shred_fwd_packets_forwarded_total {}\n\
             # HELP shred_fwd_packets_dropped_total AF_PACKET ring buffer drops\n\
             # TYPE shred_fwd_packets_dropped_total counter\n\
             shred_fwd_packets_dropped_total {}\n\
             # HELP shred_fwd_bytes_forwarded_total Bytes forwarded\n\
             # TYPE shred_fwd_bytes_forwarded_total counter\n\
             shred_fwd_bytes_forwarded_total {}\n\
             # HELP shred_fwd_last_packet_timestamp_seconds Unix timestamp of last received packet\n\
             # TYPE shred_fwd_last_packet_timestamp_seconds gauge\n\
             shred_fwd_last_packet_timestamp_seconds {}\n",
            self.packets_received.load(Ordering::Relaxed),
            self.packets_forwarded.load(Ordering::Relaxed),
            self.packets_dropped.load(Ordering::Relaxed),
            self.bytes_forwarded.load(Ordering::Relaxed),
            self.last_packet_ts.load(Ordering::Relaxed),
        )
    }
}

fn iface_index(name: &str) -> io::Result<i32> {
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = name.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "iface name too long"));
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            name_bytes.len(),
        );
    }
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::ioctl(sock, libc::SIOCGIFINDEX as _, &mut ifr) };
    unsafe { libc::close(sock) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })
}

/// Build a classic BPF filter program matching UDP packets with the given
/// destination port, and optionally restricted to a given IPv4 destination
/// address.
fn build_bpf_filter(port: u16, dst_ip: Option<Ipv4Addr>) -> Vec<libc::sock_filter> {
    // For AF_PACKET SOCK_DGRAM the data starts at the IP header.
    //
    // Without --dst-ip (10 instructions):
    //   (0) ldb [0]          ; IP version+IHL byte
    //   (1) and #0x0f        ; mask IHL
    //   (2) mul #4            ; IHL * 4 = IP header length
    //   (3) tax               ; store in X
    //   (4) ldb [9]          ; IP protocol
    //   (5) jeq #17, 0, 3    ; reject if != UDP
    //   (6) ldh [x+2]        ; UDP dst port
    //   (7) jeq #port, 0, 1  ; reject if != port
    //   (8) ret #262144      ; accept
    //   (9) ret #0            ; reject
    //
    // With --dst-ip (12 instructions, same shape plus a 32-bit IP.dst compare
    // after the UDP protocol check and before the port load):
    //   (0..4) same
    //   (5) jeq #17, 0, 5    ; reject if != UDP
    //   (6) ld  [16]         ; IP destination address (offset 16..19)
    //   (7) jeq #dst_ip, 0, 3; reject if != dst_ip
    //   (8) ldh [x+2]        ; UDP dst port
    //   (9) jeq #port, 0, 1  ; reject if != port
    //  (10) ret #262144      ; accept
    //  (11) ret #0            ; reject

    let mut filter = vec![
        // (0) ldb [0]: IP version/IHL byte
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 0 },
        // (1) and #0x0f: mask to get IHL
        libc::sock_filter { code: 0x54, jt: 0, jf: 0, k: 0x0f },
        // (2) mul #4: IHL * 4 = IP header length in bytes
        libc::sock_filter { code: 0x24, jt: 0, jf: 0, k: 4 },
        // (3) tax: copy A to X
        libc::sock_filter { code: 0x07, jt: 0, jf: 0, k: 0 },
        // (4) ldb [9]: IP protocol
        libc::sock_filter { code: 0x30, jt: 0, jf: 0, k: 9 },
    ];

    if let Some(addr) = dst_ip {
        // (5) jeq #17, next, reject(+5)
        filter.push(libc::sock_filter { code: 0x15, jt: 0, jf: 5, k: 17 });
        // (6) ld [16]: IP.dst (big-endian packet bytes -> host-order u32)
        filter.push(libc::sock_filter { code: 0x20, jt: 0, jf: 0, k: 16 });
        // (7) jeq #dst_ip, next, reject(+3)
        filter.push(libc::sock_filter { code: 0x15, jt: 0, jf: 3, k: u32::from(addr) });
        // (8) ldh [x+2]: UDP destination port
        filter.push(libc::sock_filter { code: 0x48, jt: 0, jf: 0, k: 2 });
        // (9) jeq #port, accept, reject(+1)
        filter.push(libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: u32::from(port) });
    } else {
        // (5) jeq #17, next, reject(+3)
        filter.push(libc::sock_filter { code: 0x15, jt: 0, jf: 3, k: 17 });
        // (6) ldh [x+2]: UDP destination port
        filter.push(libc::sock_filter { code: 0x48, jt: 0, jf: 0, k: 2 });
        // (7) jeq #port, accept, reject(+1)
        filter.push(libc::sock_filter { code: 0x15, jt: 0, jf: 1, k: u32::from(port) });
    }

    // accept
    filter.push(libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 262144 });
    // reject
    filter.push(libc::sock_filter { code: 0x06, jt: 0, jf: 0, k: 0 });

    filter
}

fn open_af_packet(iface: &str, port: u16, dst_ip: Option<Ipv4Addr>) -> io::Result<i32> {
    let fd = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, (libc::ETH_P_IP as u16).to_be() as i32)
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Ignore outgoing packets, only capture incoming
    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_IGNORE_OUTGOING,
            &val as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        // Without it the socket also captures what this host sends, and a
        // destination on the captured port would feed the forwarder itself.
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(io::Error::new(
            err.kind(),
            format!("PACKET_IGNORE_OUTGOING (Linux 4.20 or newer): {err}"),
        ));
    }

    // Large receive buffer to avoid drops
    let rcvbuf: libc::c_int = 16 * 1024 * 1024; // 16 MB
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Attach BPF filter
    let filter = build_bpf_filter(port, dst_ip);
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &prog as *const _ as *const libc::c_void,
            mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }

    // Bind to interface if specified
    if !iface.is_empty() {
        let ifindex = iface_index(iface)?;
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        sll.sll_ifindex = ifindex;
        let ret = unsafe {
            libc::bind(
                fd,
                &sll as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }
    }

    Ok(fd)
}

/// Packets the socket dropped since the last call. Reading PACKET_STATISTICS
/// resets the kernel's counters, so every call returns only the new drops.
fn get_packet_drops(fd: i32) -> u64 {
    let mut stats: libc::tpacket_stats = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_STATISTICS,
            &mut stats as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return 0;
    }
    stats.tp_drops as u64
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// The UDP payload of an IPv4 packet that starts at the IP header, or `None`
/// if the packet is too short for its own length fields or carries no data.
/// The UDP length field bounds the payload: a short frame arrives with link
/// layer padding behind it, and that padding is not part of the datagram.
fn udp_payload(packet: &[u8]) -> Option<&[u8]> {
    let ihl = usize::from(packet.first()? & 0x0f) * 4;
    if ihl < 20 {
        return None;
    }
    let udp = packet.get(ihl..)?;
    let udp_len = usize::from(u16::from_be_bytes([*udp.get(4)?, *udp.get(5)?]));
    let payload = udp.get(8..udp_len)?;
    if payload.is_empty() {
        None
    } else {
        Some(payload)
    }
}

fn start_metrics_server(addr: SocketAddr, metrics: Arc<Metrics>) {
    thread::Builder::new()
        .name("metrics".into())
        .spawn(move || {
            let server = match tiny_http::Server::http(addr) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("failed to start metrics server on {addr}: {e}");
                    return;
                }
            };
            log::info!("metrics server listening on {addr}");
            for request in server.incoming_requests() {
                if request.url() == "/metrics" {
                    let body = metrics.render();
                    let response = tiny_http::Response::from_string(body).with_header(
                        "Content-Type: text/plain; version=0.0.4; charset=utf-8"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    );
                    let _ = request.respond(response);
                } else {
                    let _ = request.respond(
                        tiny_http::Response::from_string("Not Found").with_status_code(404),
                    );
                }
            }
        })
        .expect("failed to spawn metrics thread");
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let destinations: Vec<SocketAddr> = args
        .destinations
        .iter()
        .map(|d| {
            d.parse::<SocketAddr>().unwrap_or_else(|e| {
                log::error!("invalid destination '{d}': {e}");
                std::process::exit(1);
            })
        })
        .collect();

    if destinations.is_empty() {
        log::error!("no destinations specified");
        std::process::exit(1);
    }

    log::info!(
        "starting shred-fwd: port={} dst_ip={} iface={} destinations={:?}",
        args.listen_port,
        args.dst_ip.map(|a| a.to_string()).unwrap_or_else(|| "any".to_string()),
        if args.iface.is_empty() { "any" } else { &args.iface },
        destinations
    );

    let af_fd = open_af_packet(&args.iface, args.listen_port, args.dst_ip).unwrap_or_else(|e| {
        log::error!("failed to open AF_PACKET socket: {e}");
        std::process::exit(1);
    });

    // Create one UDP socket for sending
    let send_sock = UdpSocket::bind("0.0.0.0:0").unwrap_or_else(|e| {
        log::error!("failed to bind send socket: {e}");
        std::process::exit(1);
    });

    let metrics = Arc::new(Metrics::new());
    start_metrics_server(
        SocketAddr::new(args.metrics_bind, args.metrics_port),
        Arc::clone(&metrics),
    );

    let mut buf = [0u8; 65535];

    loop {
        let n = unsafe {
            libc::recvfrom(
                af_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            log::error!("recvfrom error: {err}");
            continue;
        }
        let n = n as usize;
        if n < 28 {
            // Minimum: 20 byte IP header + 8 byte UDP header
            continue;
        }

        metrics.packets_received.fetch_add(1, Ordering::Relaxed);
        metrics.last_packet_ts.store(now_secs(), Ordering::Relaxed);

        let Some(payload) = udp_payload(&buf[..n]) else {
            continue;
        };

        // Forward to all destinations
        for dest in &destinations {
            match send_sock.send_to(payload, dest) {
                Ok(sent) => {
                    metrics.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                    metrics.bytes_forwarded.fetch_add(sent as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    log::warn!("send_to {dest} failed: {e}");
                }
            }
        }

        // Periodically check for AF_PACKET drops
        let received = metrics.packets_received.load(Ordering::Relaxed);
        if received.is_multiple_of(10000) {
            let drops = get_packet_drops(af_fd);
            if drops > 0 {
                let total = metrics.packets_dropped.fetch_add(drops, Ordering::Relaxed) + drops;
                log::warn!("AF_PACKET dropped {drops} packets (total: {total})");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 packet with a UDP datagram, as AF_PACKET SOCK_DGRAM delivers it.
    fn packet(
        options: usize,
        protocol: u8,
        dst_ip: [u8; 4],
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let ihl = 20 + options;
        let mut p = vec![0u8; ihl];
        p[0] = 0x40 | (ihl / 4) as u8;
        p[9] = protocol;
        p[16..20].copy_from_slice(&dst_ip);
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&dst_port.to_be_bytes());
        p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(payload);
        p
    }

    /// Runs a classic BPF program built from the instructions the filter
    /// uses and returns what it returns (0 rejects the packet).
    fn run_filter(filter: &[libc::sock_filter], packet: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let byte = |at: usize| packet.get(at).copied().map(u32::from);
        loop {
            let ins = &filter[pc];
            pc += 1;
            let k = ins.k as usize;
            let loaded = match ins.code {
                0x30 => byte(k),
                0x20 => (0..4).try_fold(0, |acc, i| Some((acc << 8) | byte(k + i)?)),
                0x48 => (0..2).try_fold(0, |acc, i| Some((acc << 8) | byte(x as usize + k + i)?)),
                0x54 => Some(a & ins.k),
                0x24 => Some(a * ins.k),
                0x07 => {
                    x = a;
                    Some(a)
                }
                0x15 => {
                    pc += usize::from(if a == ins.k { ins.jt } else { ins.jf });
                    Some(a)
                }
                0x06 => return ins.k,
                other => panic!("instruction {other:#x} is not part of the filter"),
            };
            // The kernel rejects a packet when a load reaches past its end.
            match loaded {
                Some(value) => a = value,
                None => return 0,
            }
        }
    }

    const GROUP: [u8; 4] = [233, 84, 178, 1];
    const HOST: [u8; 4] = [192, 0, 2, 10];

    #[test]
    fn filter_matches_the_port() {
        let filter = build_bpf_filter(8001, None);
        assert_eq!(filter.len(), 10);
        assert_ne!(run_filter(&filter, &packet(0, 17, HOST, 8001, b"shred")), 0);
        assert_ne!(run_filter(&filter, &packet(0, 17, GROUP, 8001, b"shred")), 0);
        assert_eq!(run_filter(&filter, &packet(0, 17, HOST, 8002, b"shred")), 0);
        assert_eq!(run_filter(&filter, &packet(0, 6, HOST, 8001, b"shred")), 0);
    }

    #[test]
    fn filter_reads_the_port_behind_ip_options() {
        let filter = build_bpf_filter(8001, None);
        assert_ne!(run_filter(&filter, &packet(8, 17, HOST, 8001, b"shred")), 0);
        assert_eq!(run_filter(&filter, &packet(8, 17, HOST, 8002, b"shred")), 0);
    }

    #[test]
    fn filter_with_destination_address() {
        let filter = build_bpf_filter(7733, Some(Ipv4Addr::from(GROUP)));
        assert_eq!(filter.len(), 12);
        assert_ne!(run_filter(&filter, &packet(0, 17, GROUP, 7733, b"shred")), 0);
        assert_ne!(run_filter(&filter, &packet(4, 17, GROUP, 7733, b"shred")), 0);
        assert_eq!(run_filter(&filter, &packet(0, 17, HOST, 7733, b"shred")), 0);
        assert_eq!(run_filter(&filter, &packet(0, 17, GROUP, 7734, b"shred")), 0);
        assert_eq!(run_filter(&filter, &packet(0, 6, GROUP, 7733, b"shred")), 0);
    }

    #[test]
    fn filter_rejects_a_truncated_packet() {
        let filter = build_bpf_filter(8001, None);
        assert_eq!(run_filter(&filter, &packet(0, 17, HOST, 8001, b"")[..21]), 0);
    }

    #[test]
    fn payload_is_what_the_udp_length_covers() {
        assert_eq!(udp_payload(&packet(0, 17, HOST, 8001, b"shred")), Some(&b"shred"[..]));
        assert_eq!(udp_payload(&packet(12, 17, HOST, 8001, b"shred")), Some(&b"shred"[..]));
        let shred = vec![0xa5u8; 1228];
        assert_eq!(udp_payload(&packet(0, 17, HOST, 8001, &shred)), Some(&shred[..]));
    }

    #[test]
    fn payload_leaves_out_link_layer_padding() {
        // A 1 byte datagram in a minimum size Ethernet frame: 46 bytes arrive
        // behind the Ethernet header, 29 of them are the packet.
        let mut padded = packet(0, 17, HOST, 8001, b"x");
        padded.resize(46, 0);
        assert_eq!(udp_payload(&padded), Some(&b"x"[..]));
    }

    #[test]
    fn payload_of_a_broken_packet_is_none() {
        assert_eq!(udp_payload(&[]), None);
        // no data
        assert_eq!(udp_payload(&packet(0, 17, HOST, 8001, b"")), None);
        // cut off in the UDP header
        assert_eq!(udp_payload(&packet(0, 17, HOST, 8001, b"shred")[..24]), None);
        // cut off in the data
        assert_eq!(udp_payload(&packet(0, 17, HOST, 8001, b"shred")[..30]), None);
        // header length below the minimum
        let mut short_ihl = packet(0, 17, HOST, 8001, b"shred");
        short_ihl[0] = 0x44;
        assert_eq!(udp_payload(&short_ihl), None);
        // UDP length below its own header
        let mut short_len = packet(0, 17, HOST, 8001, b"shred");
        short_len[24..26].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(udp_payload(&short_len), None);
    }

    #[test]
    fn metrics_render_every_counter() {
        let metrics = Metrics::new();
        metrics.packets_received.store(3, Ordering::Relaxed);
        metrics.packets_forwarded.store(6, Ordering::Relaxed);
        metrics.packets_dropped.store(1, Ordering::Relaxed);
        metrics.bytes_forwarded.store(7368, Ordering::Relaxed);
        metrics.last_packet_ts.store(1_700_000_000, Ordering::Relaxed);
        let text = metrics.render();
        for line in [
            "shred_fwd_packets_received_total 3",
            "shred_fwd_packets_forwarded_total 6",
            "shred_fwd_packets_dropped_total 1",
            "shred_fwd_bytes_forwarded_total 7368",
            "shred_fwd_last_packet_timestamp_seconds 1700000000",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}");
        }
    }
}
