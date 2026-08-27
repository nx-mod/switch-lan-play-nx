# switch-lan-play-nx

A `bsd:u` mitm sysmodule that bridges `ldn_mitm`'s real local-wireless (LDN)
traffic to an internet relay. `ldn_mitm` itself is never modified for this —
the bridge only intercepts `bsd:u` for `ldn_mitm`'s own process (see
`ShouldMitm` in `source/bsd/bsd_bridge_service.cpp`).

Ships alongside an unmodified `ldn_mitm` and its own Tesla overlay
(`overlay/`) for picking a relay server at runtime (`source/cfg/`).

**Requires `ldn_mitm` installed alongside it** — this bridge is useless on
its own; it only exists to give `ldn_mitm`'s own real LDN traffic somewhere
to go. Tracks `ldn_mitm` v1.25.1. Built against the vendored `Atmosphere-libs`
submodule as a nightly — no libstratosphere release is pinned, it always
builds against whatever's current there — so the actual minimum HOS/kernel
version is whatever that submodule's checked-out commit currently targets;
`min_kernel_version` in `res/app.json` is set to `0x0030`, matching
`ldn_mitm`'s own npdm.

## Status

**LDN is the ready, working path**: discovery (Scan/ScanResp) and joining
(Connect/SyncNetwork over a real TCP tunnel) are both implemented and
built. Everything below "Known issues / notes" documents what had to be
fixed to get there and what's still open.

**Not implemented yet** (see "Other LAN work" below): real-LAN passthrough
when both peers are on the same physical network, and bridging non-LDN
games that use plain LAN broadcast/multicast instead of LDN.

## Known issues / notes

### `ldn_mitm` could abort the whole process when its logging was enabled

Upstream `ldn_mitm`'s own `source/debug.cpp` uses `R_ABORT_UNLESS` around
every log-file filesystem call (open/write in `LogPrefix`/`LogStr`/
`LogHexImpl`, and the offset lookup in `Initialize()`). With logging
persisted across reboots (the on/off setting set via the `ldnmitm_config`
overlay), this path runs on every boot with logging enabled, and a
transient filesystem hiccup (SD card contention, the log file getting
deleted/rotated out from under the process) aborts the *entire* `ldn_mitm`
process. Since `ldn_mitm` provides `ldn:u` for every game, that takes down
all LDN play until a reboot, not just this bridge.

Fixed by hardening `ldn_mitm/source/debug.cpp` to the same pattern already
used in this project's own `source/debug.cpp`: never abort on a logging
filesystem failure, just skip that line and keep running, recreating the log
file if it's missing instead of assuming it still exists.

OR JUST KEEP LOGGING OFF IN STOCK ldn_mitm!!

### Joining a lobby requires a real TCP tunnel, not just the UDP bridge

Discovering a lobby (Scan/ScanResp) only ever needed the one bridged UDP
control socket. Actually *joining* one uses a second socket — `ldn_mitm`'s
real LDN "station" TCP connection (`lan_discovery.cpp`'s `initTcp`/
`connect`/`accept`) for the `Connect`/`SyncNetwork` handshake.

`source/bsd/bsd_bridge_service.cpp` virtualizes that socket completely: no
real network involved, tunneled as raw IPv4 packets through the exact same
relay plumbing already used for the control channel. A real peer's own
`ldn_mitm` sends genuine raw TCP (real IP protocol 6, real TCP
headers/seq/ack/checksums) on port 11452 — the same port the UDP control
channel uses, distinguished only by the IP protocol number — so
`bsd_bridge_service.cpp` builds and parses genuine TCP segments to match: a
real 3-way handshake (SYN / SYN-ACK / ACK), real sequence/ack tracking, real
TCP checksums, still riding the same `RelayBridge::SendIpv4`/`PopIpv4`
plumbing (the relay is a dumb raw-packet router keyed on destination IP; it
doesn't care what IP protocol number a packet carries).

Deliberate simplifications vs. a full RFC793 stack (acceptable given LDN's
own traffic pattern — a handful of small control messages, not bulk
transfer): no retransmission timer on our side (a real peer's own TCP stack
retransmits on its own timeout if we don't ACK in time), no out-of-order
reassembly, single-slot inbox per connection.

The checksum and handshake logic were independently verified correct: an
external Python re-implementation of the same wire format completed a full
SYN/SYN-ACK/ACK handshake and data exchange against a live relay, and the
checksum algorithm was cross-checked against a structurally different
re-implementation with matching output. Not yet confirmed against a genuine
reference client specifically, or two consoles both running this project's
build joining each other over a relay — both remain open validation steps.

### Virtual `10.13.x.x` addressing — researched, not implemented

The reference relay-play convention uses a manually-configured console IP
in `10.13.0.0/16` (subnet `255.255.0.0`, gateway `10.13.37.1`) so all
traffic — including what `ldn_mitm` embeds in its own LDN packets — carries
a collision-resistant virtual address instead of the console's real WiFi
IP. This project currently embeds the real WiFi IP everywhere instead.

Confirmed from `ldn_mitm/source/lan_discovery.cpp:525-539`: `NodeInfo.
ipv4Address` (the only address field anywhere in the LDN structs — checked
`ldn_types.hpp`) is sourced directly from `nifmGetCurrentIpAddress()`. So if
that call could be made to return a persisted virtual `10.13.x.x` address
instead, `ldn_mitm`'s own unmodified code would embed it everywhere with
zero modification needed. Two ways to get there were weighed:

- **Mitm `nifm:u` too**, reporting the virtual address to `ldn_mitm`'s
  process only. Real risk: a game's IPC request to create its `nifm`
  service handle may not match libnx's own documented signature (some
  titles call through Nintendo's own `nn::nifm`, not libnx), making the
  wire request shape for that specific call unmodelable without a hardware
  crash to learn from. Not attempted here for that reason.
- **Rewrite `ipv4Address` in-flight** from the existing `bsd:u` mitm, no new
  mitm surface. Safer, but `lan_protocol.cpp`'s `sendPacket()`
  RLE-compresses nearly every outgoing packet (confirmed: captures showed
  ~289 bytes for a 1152-byte `NetworkInfo`), so patching the field means
  decompress → patch → re-compress, not a plain byte swap. The RLE format
  itself is simple and fully understood (read directly from
  `lan_protocol.cpp`'s own `compress`/`decompress`), so this is tractable,
  just a second subsystem to get right.

Not started. Both paths are unverified against a real PC client either
way — nobody has tested this project against genuine reference client
software yet.

## Other LAN work (not started)

Two separate, larger features, deliberately out of scope until LDN itself
is confirmed solid on real hardware against a real peer:

- **Real-LAN passthrough.** When both peers are actually on the same
  physical network, the relay is unnecessary overhead — `ldn_mitm`'s own
  real broadcast should just work directly. Right now this bridge routes
  everything through the relay unconditionally once installed; with the
  relay stopped or unreachable, local play just fails instead of falling
  back to the real network. Needs: detect same-subnet peers (from a
  discovered `NetworkInfo`'s embedded IP, or a live local-reachability
  probe) and skip bridging that connection entirely.
- **LAN-over-relay for non-LDN games.** Some titles use plain UDP
  broadcast/multicast for local multiplayer instead of LDN. This bridge
  only mitms `bsd:u` for `ldn_mitm`'s own process — it has no path for
  bridging an arbitrary game's own broadcast traffic. Needs a broadened
  `ShouldMitm` (matching more than one fixed program ID, with its own
  filtering so this doesn't accidentally bridge homebrew) plus new
  broadcast/multicast interception logic. Can mostly reuse the existing
  `RelayFrameType::Ipv4` raw-packet plumbing once that's built.

## TODO

- [ ] Validate the real-TCP join path against a genuine reference client
      (not yet tested).
- [ ] Validate two consoles both running this project's build joining each
      other over a relay (not yet tested).
- [ ] Decide on virtual `10.13.x.x` addressing (see above) — needed for
      broader interop with peers that expect it.
- [ ] Real-LAN passthrough (see "Other LAN work").
- [ ] LAN-over-relay for non-LDN games (see "Other LAN work").
- [ ] Clear on-device logs/fatal dumps as part of the normal deploy flow,
      not a manual afterthought.
