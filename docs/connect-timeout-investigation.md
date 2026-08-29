# Real console-to-console join failures: `ldn_mitm` connect() 1-second timeout

Investigated 2026-08-28/29, during live testing between two real consoles
(both running the current `switch-lan-play-nx` build with the fragmentation,
reassembly-slot-eviction, and `SignalLost`/`POLLHUP` fixes already deployed).
Despite those fixes, two real consoles only completed one successful join
all night, and it dropped after ~2 seconds. This document captures the
actual root cause, confirmed directly from the console's own live trace log.

## The evidence

Pulled `switch-lan-play-nx.log` live via FTP during a real join attempt
between two real consoles (station IP `10.233.41.168`, host IP
`192.168.68.124`, i.e. two genuinely different real networks -- not PC-side
test tooling). The same pattern repeats over and over across the whole log
(timestamps and ISNs vary per attempt, structure is identical):

```
Connect(tcp fd=1) -> dst 0xc0a8447c:11452 isn=4292850190, sending SYN
TCP SYN-ACK from 0xc0a8447c:11452 -- handshake complete
Connect(tcp fd=1) -> established with 0xc0a8447c:11452
SendTo(tcp fd=1, 35 bytes -> peer 0xc0a8447c:11452 seq=4292850191) relay_sent=76
Close(tcp fd=1) -- tearing down connection to 0xc0a8447c:11452      <- ~1.1s later
```

Between "SendTo" (the 35-byte `LANPacketType::Connect` packet, containing our
`NodeInfo`) and "Close", there is **no** `RecvFrom(tcp fd=1)` logged -- our
bridge never received `SyncNetwork` on that connection before it was torn
down. The full virtual-TCP handshake worked correctly (our bridge's own
SYN/SYN-ACK/ACK code, plus the fragmentation and `SignalLost` fixes, are
doing their job) -- what's missing is the host's `SyncNetwork` reply arriving
in time.

## Root cause: stock `ldn_mitm`'s `connect()`

From the actual stock `ldn_mitm` source
(`ldn_mitm/source/lan_discovery.cpp`, `LANDiscovery::connect()`):

```cpp
ret = this->tcp->sendPacket(LANPacketType::Connect, &myNode, sizeof(myNode));
...
this->initNodeStateChange();
svcSleepThread(1000000000L); // 1sec
return 0;
```

`connect()` sends the `Connect` packet, sleeps **exactly one second**, and
returns -- unconditionally successful, regardless of whether `SyncNetwork`
ever actually arrived. It does not wait on the async `NodeStateChange`
event it just armed one line earlier; it just races a fixed sleep against a
completely separate async event. Whatever calls this (the game, via
`nn::ldn`) then checks connection state; if `SyncNetwork` hasn't landed
within that window, it isn't yet `StationConnected`, and the game itself
retries the whole join from scratch. That retry loop is exactly what the
log shows, over and over.

## Why the original PC client never hits this

`switch-lan-play` (the PC client) pairs with the *same* upstream `ldn_mitm`
-- same 1-second sleep, unmodified. But on that architecture, the console's
`connect()` target is a companion PC on the *same real LAN* as the console.
That hop is sub-millisecond, so the 1-second window is trivially satisfied
locally every time. The actual internet-crossing hop to the *remote* peer
happens entirely on the PC-client software's own side, asynchronously,
after `ldn_mitm`'s `connect()` call has already returned successfully. The
PC client's architecture decouples `ldn_mitm`'s hard-coded synchronous
timing constraint from the part of the exchange that actually has to cross
the internet.

We don't have that luxury: `switch-lan-play-nx` runs directly on the
console and mitms `bsd:u` underneath a stock `ldn_mitm`, so *we* are the
thing that has to complete a full real internet round trip (station SYN ->
host processes -> host's SyncNetwork back to station) inside that same
fixed 1 second. Any realistic relay latency violates that most of the
time. This fully explains "worked once, dropped after 2 seconds, fails
otherwise" without needing any other theory (IP addressing, PIA nonces,
etc. -- all real findings from tonight, but none of them are the cause of
*this specific* failure).

## Existing fix: already solved in `ldn_mitm-dogty`

`C:\PROJECTS\switch\lan-play\ldn_mitm-dogty\ldn_mitm\source\lan_discovery.cpp`,
`LANDiscovery::connect()`, lines ~1503-1570 (the TCP-based connect path --
NOT the separate built-in-relay-client path further up in the same
function, which is dogty-architecture-specific and not applicable to us).
Relevant part, wire-protocol-identical to stock:

```cpp
ret = this->tcp->sendPacket(LANPacketType::Connect, &myNode, sizeof(myNode));
if (ret < 0) { ... return ResultConnectFailed; }
{
    std::scoped_lock lock(this->dataMutex);
    this->initNodeStateChange();
}

/* Wait for the host's SyncNetwork instead of a fixed 1s sleep;
   on a LAN this typically completes within a few ms. */
bool synced = false;
for (int j = 0; j < 300; j++) {
    if (this->state == CommState::StationConnected) {
        synced = true;
        break;
    }
    svcSleepThread(10000000L); // 10ms
}

/* The original code returned success unconditionally here. If the
   host never syncs (e.g. it went to sleep after advertising), the
   game would be told it joined and hang waiting for nodes forever.
   Fail instead so it can show a proper error. */
if (!synced) {
    LogFormat("connect: no SyncNetwork from host, aborting join");
    std::scoped_lock lock(this->pollMutex);
    if (this->tcp) { this->tcp->close(); }
    return ResultConnectFailed;
}
return 0;
```

Why this is safe to adopt (does **not** repeat dogty's actual
compatibility break, which was abandoning the virtual-IP scheme /
`LocalNetworkMode` entirely -- an architecture/wire-protocol-level change):

- No `NodeInfo`/`NetworkInfo` struct changes.
- No wire protocol changes -- still sends the same `Connect` packet over
  the same real TCP connection.
- Purely local: replaces a blind fixed sleep with a polling wait on state
  that `ldn_mitm` was *already* tracking (`this->state`,
  `initNodeStateChange()`), up to 3 seconds instead of 1, and returns
  failure instead of lying about success when it times out.
- Does not add dogty's built-in relay client to `ldn_mitm` -- our relay
  logic stays entirely in `switch-lan-play-nx`, one layer below, exactly
  as designed.

Not yet ported to our `ldn_mitm` tree
(`C:\PROJECTS\switch\switch-cfw\ldn-mitm\ldn_mitm\source\lan_discovery.cpp`)
as of this writing.

### Worth folding into the same patch: verify we're actually in the node list

Dogty's fix also tracks `joinAwaitSelfIp` and, in `onSyncNetwork`, checks
that the joining peer's own IP is actually present in the received
`NetworkInfo`'s node list before treating the join as real -- not just "did
any `SyncNetwork` arrive." Cheap, safe, purely local addition on top of the
polling-wait fix above: when checking `this->state == CommState::StationConnected`
in the loop, also confirm `this->networkInfo.ldn.nodes[i].ipv4Address` matches
our own IP for some `i`. Guards against a stale/unrelated sync being
misread as confirmation.

### Checked and NOT needed: explicit disconnect notification

Dogty's fork also has an explicit `RelayBye` packet sent on disconnect, so
peers don't have to rely purely on passive timeout to notice someone left.
We already have the equivalent for our actual gap (per-station TCP
connections): `LanStation::reset()` (stock `ldn_mitm`,
`lan_discovery.hpp:52-55`) does `this->socket.reset()`, destroying each
station's own TCP socket object -- a real `close()` on that station's real
fd. Our bridge's `Close()` handler already sends a proper `TCP_FIN | TCP_ACK`
over the relay whenever a tracked connection closes. Since
`resetStations()` (called by `destroyNetwork()` / `closeAccessPoint()` /
etc.) closes every station's socket individually, every connected peer
already gets an explicit FIN automatically -- no passive-timeout-only gap
found here. Dogty's `RelayBye` solves the equivalent problem for their
*UDP-based relay control channel*, which is architecturally a different
layer than our TCP station connections.

## Also confirmed tonight, not the cause of this bug but real

- `nodes[0].ipv4Address` (station's join target) is used in exactly one
  place in stock `ldn_mitm` -- the raw `::connect()` call -- with zero
  range/shape validation.
- `ICommunicationService::GetNetworkInfo()` hands the calling game the
  *full* `NetworkInfo`, including every peer's raw IP -- meaning a game
  *could* open its own direct socket to a peer IP, bypassing `ldn_mitm`'s
  control channel entirely. Not confirmed for MK8DX's actual LDN gameplay
  traffic specifically; confirmed as the real mechanism used by MK8DX's
  separate LAN-mode Pia session layer (`sys-slp-client/spike/demo_host.py`).
- Nintendo's real Pia session-layer AES-GCM nonce embeds the sender's own
  source IP directly (`slp_pia.py`: `nonce = src_ip + src_var&0xFF + ...`).
  Only matters if/when a Pia-encrypted gameplay socket is ever bridged --
  not relevant to the control-channel connect() failure documented here.
- Stock `ldn_mitm`'s `LDUdpSocket::onClose()` is missing a `this->close()`
  call and unconditionally sets `DisconnectReason::SignalLost` regardless
  of actual cause -- separately root-caused earlier tonight, fix already
  implemented on our side as a `Poll()`-level `POLLERR`/`POLLHUP`
  suppression in `switch-lan-play-nx` (not an `ldn_mitm` modification),
  already deployed in the current build.
- `LANDiscovery::initialize()` in stock `ldn_mitm` calls
  `nifmSetLocalNetworkMode(&request, true)` (an undocumented nifm IPC,
  option byte 2) and force-overwrites the current network profile's MTU to
  1500, before every AP/station session. This already runs identically in
  our current setup (we've never touched `LANDiscovery::initialize()`) --
  not something missing, just background context. No evidence tonight that
  it interferes with relay traffic (FTP and relay traffic both kept
  working concurrently through real sessions).
