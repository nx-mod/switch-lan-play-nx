# ldn_probe

A minimal LDN control-plane exerciser for Nintendo Switch, built as a homebrew
NRO so that **one binary runs in two places** and drives the same `ldn:u`
surface in both:

```
real console : ldn_probe -> ldn:u -> ldn_mitm -> bsd:u -> slp-nx -> relay
Eden         : ldn_probe -> HLE ldn:u -> LANDiscovery -> helper -> relay
```

Both ends meet at a switch-lan-play relay. If one side hosts and the other's
scan lists that network, the bridge is proven end to end.

## Why it exists

Testing the LDN path previously required Mario Kart 8 Deluxe on two real
consoles. The scripted stand-ins (`slp_ldn.py`, `fake_ldn_host.py`) can
complete LDN-level Connect and SyncNetwork, but they cannot produce real Pia
gameplay data, so every join ended the same way: pick character, "please
wait", communication error.

`ldn_probe` sidesteps that entirely by **stopping at the LDN control plane**.
It never opens a gameplay socket, so it never needs Pia. A network appearing
in a scan, and a host's node count incrementing, is the whole success
condition.

That also buys a clean bisect: if probe-to-probe works over the relay but a
real game still fails, the fault is in the Pia data plane, not in LDN.

## Controls

| Button | Action |
|--------|--------|
| **A** | Host — `OpenAccessPoint` + `CreateNetwork` + `SetAdvertiseData` |
| **B** | Scan — `OpenStation` + `Scan`, lists every network found |
| **X** | Join the first scan result — `Connect` |
| **Y** | Leave — `Disconnect` or `DestroyNetwork`, whichever applies |
| **+** | Exit |

The display shows live LDN state, the assigned virtual IP, the node table as
peers join, and each scan hit's `local_communication_id`.

Two deliberate choices:

- **Scan filter flags are 0** — nothing is filtered, so real games show up
  alongside probe networks. A diagnostic wants the whole picture.
- **`local_communication_id` is fixed** at `0x4C444E5F50524F42` (reads as
  `LDN_PROB` in a hexdump) so probe networks are trivially greppable in logs
  and distinguishable from a game's.

Hosting sends two `SyncNetwork` packets in quick succession — `CreateNetwork`
then `SetAdvertiseData`, each triggering `updateNodes()` — which is
deliberate: that back-to-back pair is what coalesces into a single TCP
segment and exercises the bridge's receive-stream reassembly.

## Build

Requires devkitPro with devkitA64 and libnx.

```sh
make
```

Produces `ldn_probe.nro`. Copy to `/switch/ldn_probe/ldn_probe.nro` on the SD
card and launch from hbmenu.

## Notes

Both sysmodules mitm this like they would a game — no special casing needed.
`ldn_mitm`'s `ShouldMitm` returns `true` unconditionally, and slp-nx bridges
every process's `bsd:u` with per-fd scoping in `Bind()`, so homebrew is
covered by the same path a commercial title takes.
