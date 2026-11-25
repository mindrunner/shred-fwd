# shred-fwd

Copies UDP packets received on one port and sends their payload to other hosts.

It was written for Solana shreds. A validator gets them on its TVU port, and you may want the same shreds on a second machine too (an RPC node, a backup validator, a tool that measures them). `shred-fwd` listens with an `AF_PACKET` socket: the kernel hands it a copy of each packet, and the validator's socket still gets the original. The validator needs no change and no restart.

With `--dst-ip` it takes only packets for one IPv4 destination address. Point it at a multicast group and you have a bridge from the group to unicast receivers.

## Usage

```console
# shred-fwd --listen-port 8001 --iface eth0 --dest 192.0.2.10:8001 --dest 192.0.2.11:8001
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--listen-port` | `8001` | UDP destination port to capture. `--src-port` is an older name for it. |
| `--dest` | required | Where to send the payload, as `ip:port`. Give it once per receiver. |
| `--iface` | all interfaces | Capture on this interface only. |
| `--dst-ip` | any | Capture only packets for this IPv4 destination address. |
| `--metrics-port` | `9400` | Port of the metrics endpoint. |
| `--metrics-bind` | `127.0.0.1` | Address the metrics endpoint listens on. |

`RUST_LOG` sets the log level (`info` if unset).

The process needs `CAP_NET_RAW` to open the packet socket and nothing else, so it can run as an unprivileged user under systemd:

```ini
[Service]
ExecStart=/usr/local/bin/shred-fwd --listen-port 8001 --dest 192.0.2.10:8001
DynamicUser=true
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
Restart=always
```

## Packet handling

A filter in the kernel (classic BPF) passes IPv4 packets that are UDP and have the right destination port, plus the right destination address if you gave one. Packets sent by the host are ignored. For each packet that passes, `shred-fwd` takes the UDP payload and sends it to every `--dest` from one UDP socket, so the receivers see the forwarding host as the source, not the original sender.

Three limits follow from that design:

- IPv4 only.
- Fragmented datagrams are not put back together.
- Don't send to the captured port on the same host: the forwarder would capture what it sent and loop. Use another port there.

The receive buffer is set to 16 MB, but the kernel caps it at `net.core.rmem_max`. Raise that sysctl if `shred_fwd_packets_dropped_total` grows.

## Metrics

`http://127.0.0.1:9400/metrics`, in the Prometheus text format:

| Metric | Meaning |
| --- | --- |
| `shred_fwd_packets_received_total` | packets captured |
| `shred_fwd_packets_forwarded_total` | sends that worked (one per packet and destination) |
| `shred_fwd_bytes_forwarded_total` | payload bytes sent |
| `shred_fwd_packets_dropped_total` | packets the kernel dropped on the capture socket; read every 10,000 captured packets |
| `shred_fwd_last_packet_timestamp_seconds` | unix time of the last captured packet |

## Install

Each release has `shred-fwd-<tag>-x86_64-unknown-linux-gnu.tar.gz` and a `.sha256` file next to it. The binary comes from an Ubuntu 24.04 runner and needs glibc 2.39 or newer. The kernel has to be Linux 4.20 or newer, for `PACKET_IGNORE_OUTGOING`.

To build it yourself:

```console
$ cargo build --release
```

The Rust version is pinned in `rust-toolchain.toml`.

## Development

```console
$ cargo fmt --check
$ cargo clippy --all-targets -- -D warnings
$ cargo test --all-targets
```

The tests run the BPF filter in a small interpreter against packets made by hand. They need no privileges and no network.

## Release

Push a `v*` tag. The release workflow packs the tarball, writes its checksum and attaches both to the GitHub release.

## License

Apache-2.0.
