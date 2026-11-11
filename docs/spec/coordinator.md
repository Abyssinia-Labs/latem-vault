# Coordinator spec, v1

Status: draft, 2026-11-10. Milestone M3 (design §18), built in stages: the relay and the log copy first, then addresses and presence, then joins away from home. Builds on [service.md](service.md), [sync.md](sync.md), [join.md](join.md) and [membership.md](membership.md). The design is in [design §5](../design.md#5-architecture), [§10](../design.md#10-networking), [§11](../design.md#11-coordinator) and [§12](../design.md#12-platforms).

The grandfather is the vault's always-on machine: the Mac mini here. `openvault grandfather` runs two things there for one vault:
- **a relay**, which forwards traffic between devices that can't reach each other directly;
- **a coordinator**, which keeps a copy of the membership log, a directory of where each device can be reached, who is online, and a board where devices waiting to join can be found.

Both are untrusted (OV-2). Devices check every log entry themselves (OV-3), data goes device to device encrypted end to end (OV-7), and joins stay bound to a code the coordinator never sees (join.md). Everything the grandfather does is about reachability: losing it, or an attacker owning it, costs availability and metadata, never secrets.

M3 is done when the MacBook, away from home, syncs with the mini.

All integers are big-endian.

## What changes for devices

A device with a coordinator configured (below):
- **uses the grandfather's relay** as its home relay, and no other. It still never connects to n0's relays (service.md, endpoint).
- **tells the coordinator where it can be reached**, and only it. There is still no DNS or pkarr publishing.
- **learns from the coordinator which members are online**, as well as from mDNS. Sync treats both the same way (devices, below).
- **can be found while joining away from home**, through the join board. The join itself is unchanged (join.md).

A device with no coordinator configured works as in M2: local network only, no relay.

## Running the grandfather

```
openvault grandfather --vault <vault id> --hostname <name> [--port 443] [--data <dir>]
                      [--cert <file> --key <file>]
openvault grandfather install [same options]     start it at login, as service.md's install does
```

- **Its data directory** is `--data`, by default `grandfather` in the openvault directory.
- **Its identity.** At its first start it creates an iroh secret key in `grandfather.key` in its data directory (mode 0600). Its endpoint id is the coordinator's identity. It is not a device: it isn't in the log and holds no collection keys.
- **Its address**, which devices are given, is `ov1:<endpoint id in hex>@<hostname>[:<port>]`, with the port left out when it's 443. `openvault grandfather` prints it when it starts.
- **Its port.** The port is TCP for the relay's HTTPS and UDP for the coordinator. The relay has no QUIC address discovery, so there is no UDP 7842 (relay, below).
- **One vault.** `--vault` names it at the first start, and the data directory remembers it. The coordinator takes only a log whose genesis has that vault id (membership.md, creating a vault), so a device of another vault can't take it over.
  - Until a device gives it the log, it takes the first genesis with that id. The vault id isn't secret (sync.md's hello carries it), so an endpoint that got there first could leave it holding another log. Devices would then be refused, which costs availability only; removing `coordinator.db` starts it over.
- **Where it runs.**
  - **On a Linux host,** in Docker: the image's `grandfather` mode (below).
  - **On the Mac mini, natively,** with `openvault grandfather install`. Docker Desktop on macOS passes connections through its own network, so the relay would see that network's address instead of each device's, and could no longer tell devices their own public address, which hole punching needs.
- **Reaching it from outside.**
  - `--hostname` must resolve to the home connection's public address (an A record, and an AAAA record where IPv6 works), kept current by dynamic DNS.
  - The router forwards TCP and UDP on the port to the grandfather.
- **TLS.** Without `--cert`, the relay gets a certificate for `--hostname` from Let's Encrypt, answering its challenge on the port (TLS-ALPN-01), so the port must be 443 as seen from outside. It keeps the certificate in the data directory. With `--cert` and `--key`, it uses those PEM files and reads them again every hour, for a certificate issued another way, such as a DNS challenge.

## Relay

- **The server** is iroh's relay (`iroh-relay`), run in the same process. It speaks HTTPS on the port.
- **No QUIC address discovery.** iroh's relays usually answer it on UDP 7842, telling a device its public address for holepunching, and iroh keeps a connection to it open from every device: about 0.6 KB a second each when measured. Without it, devices behind different NATs reach each other through the relay. Devices still send the relay an HTTPS probe every 20 to 26 seconds, which is how iroh picks it as their home relay.
- Its plain-HTTP side, which iroh's relays offer for captive-portal checks, listens on the loopback interface only. Devices skip that check.
- **What it sees.** Traffic between two devices is QUIC, encrypted end to end between their transport keys. The relay sees which endpoints talk, when, and how much.
- **Who may use it.** It admits:
  - devices that are members in the coordinator's log copy and aren't revoked, by transport key;
  - endpoints on the join board, until their entry ends;
  - the coordinator's own endpoint.

  It denies everyone else, so it isn't a free relay for the internet. iroh tries a refused connection again about every 16 seconds.
- **When the list is read.** The relay checks an endpoint when it connects. A device revoked while connected keeps its connection until it drops; other devices refuse it anyway (sync.md), and a revoked device's own service leaves the relay (devices, below).
- **Presence.** The relay knows which admitted endpoints are connected. That is what "online" means here, and it is kept in memory only, never written.
- **Its log** leaves out iroh-relay's error for each HTTPS connection that failed. On a public port 443 those come from scanners and from handshakes that end early, Let's Encrypt's checks among them: 35 in the first hour of the first run, none of them the relay's own fault. `OPENVAULT_LOG` shows them again.

## Coordinator

The coordinator is an iroh endpoint with ALPN `openvault/coord/1`, listening on UDP on the grandfather's port. Devices reach it directly, at the hostname and port in its address, and never through the relay: the relay admits only members, and the coordinator is how it learns who they are, so a device it hasn't heard of yet couldn't reach it that way.

**Who may do what.**
- A connection from a member, by its transport key in the coordinator's log copy, may use every message below.
- Any other endpoint may only post to the join board.
- A revoked device gets error "not a member" (sync.md) after hello, and nothing else.

**Lifetime.** A device connects to the coordinator for an exchange and closes the connection once the logs are level: when its service starts, when its own log changes, and every 15 minutes to hear of entries it doesn't have. It keeps no connection open: an open iroh connection keeps every path alive every 5 seconds and retries holepunching between the address pairs both sides have every 5 seconds, which iroh's settings can't turn down, and measured about 1.9 KB a second per device. If an exchange fails, the device logs why and tries again after 30 seconds, doubling up to an hour, as for sync retries; changes to its log meanwhile wait for that. A service that is stopping ends an exchange without a retry.

### Messages

Framing, hello, the log messages and errors are sync.md's. The rest:

| Type | From | Message | Body |
| --- | --- | --- | --- |
| `0x30` | device | address | relay url (str) ‖ count (u8, at most 8) ‖ direct addresses (str) |
| `0x31` | device | look up | endpoint id (32) |
| `0x32` | coordinator | found | endpoint id (32) ‖ has address (u8) ‖ relay url (str) ‖ count (u8) ‖ direct addresses (str), present only if has address is 1 |
| `0x33` | device | watch | — |
| `0x34` | coordinator | online | count (u16) ‖ changes: endpoint id (32) ‖ online (u8) |
| `0x35` | joiner | post | platform and name hint (str, at most 86 bytes, as join.md's announcement) |
| `0x36` | device | list joins | — |
| `0x37` | coordinator | joins | count (u8) ‖ entries: endpoint id (32) ‖ hint (str) ‖ seconds left (u16) |

`str` is `u16 length ‖ UTF-8`.

**Logs.** After hello, whichever side is behind requests entries, as two devices do (sync.md, log exchange).
- Devices answer the coordinator's requests: it's the endpoint in the address they were given, and the log isn't secret from it (what the grandfather sees, below). The coordinator answers members only.
- A coordinator with no log yet sends hello with seq 0 and a hash of zeros, and requests from seq 0.
- The coordinator checks each entry as a device does (membership.md, accepting an entry), so it keeps only a log that admins signed.
- Once the logs are level, a device that isn't a member in the copy gets error "not a member". Otherwise the coordinator sends hello again, and the device closes the connection. Its first hello comes before it has read the device's, so only a later one ends the exchange.
- A device that took entries from the coordinator sends hello once it has caught up, for that answer. One whose log grew during the exchange sends hello again, and the coordinator asks for the rest.
- A device waits at most 30 seconds for the coordinator's next message.
- When the coordinator's log grows, it sends hello to every other device connected to it at the time. Other devices hear of the entries at their next exchange, or from a member they sync with.
- The copy also tells the relay who the members are.
- A fork is refused like any other entry that doesn't extend the chain. The coordinator keeps the log it has.

**Addresses.**
- A device sends address after hello, and again whenever its relay url or direct addresses change.
- The coordinator writes it only if it differs from the row it has (design §11).
- look up answers from that row. Devices use it as an iroh address lookup, so dialing a member by endpoint id works wherever it is.

**Watching.**
- After watch, the coordinator sends online with every member that is online now, then one online message per change while the connection lasts.
- A member going offline is a change too.

**The join board.**
- A joiner that was given the coordinator's address (`openvault join --coordinator`) connects, posts its hint, and keeps the connection open while it waits.
- Its entry ends when that connection closes, or after 10 minutes.
- The board holds at most 16 entries. A post when it's full gets error "bad message", and the joiner says the board is full.
- list joins answers with the entries left.
- A hint is untrusted, as join.md says of mDNS announcements: the code and the PAKE decide.

## Devices

**Configuring.**
- `openvault coordinator set <address>` keeps the address in a file `coordinator` in the openvault directory. `openvault coordinator` shows it, and whether the coordinator answers.
- `openvault coordinator unset` goes back to the local network only.
- The address is per device. Keeping it in the membership log, signed by an admin, so every device learns it, is not in v1.

**In the service**, with a coordinator configured:
- The endpoint's relay is the grandfather's relay, from the address.
- It dials members with the relay's url as well as the addresses mDNS finds.
- It adds a coordinator address lookup next to mDNS. Replacing a stopped mDNS (service.md, discovery) then replaces only the mDNS lookup.
- It exchanges with the coordinator at start, when its log changes, and every 15 minutes (lifetime, above). In stage 1 an exchange is hello and logs.
- If the coordinator says this device isn't a member, the service logs it, stops using the relay, and stops connecting to the coordinator until it starts again.
- **Reachable members.** A member is reachable while mDNS shows it or the coordinator says it's online. Every rule in sync.md about visible members applies to reachable ones: sessions start when a member becomes reachable and after local writes and log entries, retries stop when it isn't reachable, and a member that isn't reachable is never dialed.

**Joining away from home.**
- `openvault join --coordinator <address>` posts to the board and also announces itself on mDNS, as now.
- `openvault approve` lists the board's entries along with mDNS's, if this device has a coordinator configured.
- The join runs as join.md says, over iroh, through the relay when it must. The PAKE binds both transport keys to the code, so neither the relay nor the coordinator can get in the middle.
- The new device takes the coordinator's address as its own.

## `hold` copies

- The grandfather process keeps none: it isn't a device and has no keys.
- `hold` copies are kept by a device on the grandfather's host with `hold` scope on the collections it doesn't read. On the mini, that's the Mini device. On a Linux host, it's the Docker image's `device` mode.
- Sync needs nothing new: devices with `hold` already reconcile, using headers only (sync.md, accepting records).

## Docker image

One image, `openvault`, for linux/amd64 and linux/arm64, with two modes:
- **`grandfather`:** `openvault grandfather`, with its data directory in a volume. It needs host networking, or ports published without address translation, for the relay.
- **`device`:** `openvault service` with software keys (keystore.md) in a volume, for a host that keeps `hold` copies with no native install.

A compose example and a self-hosting guide (`docs/self-hosting.md`) come with it.

## Storage

One SQLite database, `coordinator.db` in the data directory, mode 0600:

| Table | Holds | Bounded by |
| --- | --- | --- |
| vault | the vault id, and the membership the log describes after its last entry | one row |
| log | each entry by seq | the log, which grows only with membership changes. Reads are pages of at most 64 |
| addresses | each member's relay url and direct addresses, by endpoint id | one row per member. A revoked member's row is removed when its revocation is applied |

The join board and presence are in memory only.

## What the grandfather sees

| It sees | It can | It can't |
| --- | --- | --- |
| Each device's transport key and IP addresses, and when it's online | Delay, drop or replay messages; give wrong addresses; refuse to relay; hide who's online | Add a device or change a scope: entries need an admin's signature |
| The membership log: collection ids, scopes and key epochs. Device names are sealed (membership.md, names key) | Block joins | Read a record, a grant or a value: they go device to device, encrypted end to end |
| The join board's hints | Fill the board, to the 16-entry limit | Get between a joiner and an admin: the PAKE binds their transport keys to the code |
| How much each pair of devices relays | | |

## Cost

| Case | Cost |
| --- | --- |
| Idle, per device | About 75 bytes a second to the grandfather, in and out together: some 6 MB a day. The relay connection is pinged every 15 seconds, about 6 B/s. iroh sends the relay an HTTPS probe every 20 to 26 seconds, about 50 B/s. An exchange with the coordinator every 15 minutes is about 16 KB in all: about 17 B/s. No database reads. Measured on 2026-11-10 on the MacBook, over 12 minutes of nothing changing. Before exchanges and without address discovery taken out, it was about 2.5 KB a second: 1.9 KB/s for an open coordinator connection, and 0.6 KB/s for QUIC address discovery (lifetime and relay, above). |
| A refused endpoint | A TLS connection to the relay about every 16 seconds, until it's a member. A revoked device's service stops after the coordinator refuses it. |
| A network change | One address message, and one row write if the address changed. |
| A log entry | An exchange from the device that made it, and from each other device at its next one: one paged read of at most 64 entries each. |
| Presence | One online message per change, to each watching device. Nothing written. |
| Joining | One board entry in memory for up to 10 minutes; the join's own traffic through the relay if it can't go direct. |
| Relay | The bytes of sessions that can't go direct: the only cost that grows with data. |

**What to watch once it runs:**
- `coordinator.db`'s size. It should stay about the log's size plus one row per device. Growth means addresses are being written when they don't change.
- Bytes relayed per day. They should follow writes, and fall when direct paths work.
- Coordinator connections: about 4 an hour per device while nothing changes, more after local log changes and failures.
- A device's bytes a second to the grandfather while nothing changes: about 75 (`nettop -p <pid>` on the device). Kilobytes a second mean a connection is being kept open.
- Address writes per device per day: a handful.

## Not settled

- **Presence and addresses (stage 2).** Watching, as above, keeps a connection to the coordinator open, which is what cost 1.9 KB a second per device. Stage 2 needs another way: a device could ask for addresses and who's online during an exchange, or dial a member through the relay when there is something to sync, which reaches it whenever it's connected to the relay and needs no presence at all.
- **HTTPS probes.** iroh probes the relay every 20 to 26 seconds, which is how it keeps the relay as the home relay: about 50 bytes a second per device. It offers no setting to probe less often, and without probes a device has no home relay.

## Not in v1

- **A store-and-forward mailbox:** approval requests and wrapped keys for a device that isn't online. Joins run live through the relay instead. Approving from a notification comes with the Apple apps (M5).
- **The coordinator's address in the membership log.**
- **More than one grandfather or relay** for a vault.
- **Push wake-ups for iOS,** and serving many vaults (M6).
