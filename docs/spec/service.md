# Service spec, v1

Status: draft, 2026-11-07. Implemented by `crates/net` (the endpoint and discovery) and `crates/service` (the service and its local API). Builds on [records.md](records.md), [membership.md](membership.md) and [keystore.md](keystore.md). Sync ([sync.md](sync.md)) and joining ([join.md](join.md)) run inside it once they are built. The design is in [design §5](../design.md#5-architecture), [§10](../design.md#10-networking) and [§14](../design.md#14-interfaces).

`openvault service` is the one process on a device that holds the vault open. It:
- unlocks the device's keys once, so a passphrase is typed once per run rather than once per command;
- runs the device's iroh endpoint and finds the vault's other devices on the local network;
- answers the CLI over a local socket.

All integers are big-endian.

## Running it

- `openvault service` runs in the foreground and logs to stderr. It stops on Ctrl-C or SIGTERM, and removes its socket as it goes.
- It opens the vault as any command does: from the Secure Enclave, or after asking for the passphrase (keystore.md, passphrases).
- One service runs per vault. It holds a lock on `service.lock` in the openvault directory while it runs, and a second service that can't take the lock exits. The operating system drops the lock when a service crashes, so a socket found while holding it is left over, and is replaced.
- Starting it at login, as a LaunchAgent or a systemd user unit, comes later. The macOS app (M5) bundles it as a LaunchAgent.

**The store.** The service keeps one connection to the store and handles requests one at a time. Before each request it checks SQLite's `data_version`, which changes when another process has written. If it has changed, the service reloads the membership it keeps in memory. A command run while the service starts up, before the socket is there, therefore can't leave the service with a stale log.

## Endpoint

Each device runs one iroh endpoint (design §10):

- **Identity.** Its secret key is the transport key (records.md, local store), so its endpoint id is the transport key in the device's add_device entry.
- **No relays.** It uses no relay, so it never connects to n0's relays. The grandfather's relay comes in M3.
- **No publishing.** It uses no DNS or pkarr address lookup and no port mapping. Nothing outside the local network learns the endpoint id or addresses.
- **Protocols.** It accepts connections with ALPN `openvault/sync/1` (sync.md) and runs a session on each. Joining uses `openvault/join/1` on endpoints of its own (join.md, commands).

### Discovery

- The endpoint finds others with mDNS, under the service name `openvault`: `<endpoint id>._openvault._udp.local.`.
  - Other iroh applications use their own service names, so they don't see OpenVault devices and OpenVault doesn't see them.
  - Devices that are members announce nothing besides their endpoint id and addresses. A joining device also announces its platform and name (join.md, finding the device).
- mDNS queries go out every 5 seconds, plus a random delay that grows with the number of peers. A peer that stops answering expires after a few cycles.
- **When mDNS stops.** swarm-discovery, under iroh's mDNS lookup, stops all of mDNS when one of its sockets fails: the device stops announcing itself and hears nobody. It happens, for instance, on a Mac whose service starts while macOS is still deciding whether it may use the local network. The only sign is a warning from swarm-discovery, so the service watches its log for it, whatever `OPENVAULT_LOG` shows. Then:
  - The members it could see count as gone, since the stopped lookup can't say who leaves.
  - After 5 seconds it starts a new lookup in place of the stopped one, and finds them again.
  - If mDNS keeps stopping, the wait doubles each time, up to 5 minutes. Once mDNS has run for 10 minutes, the next wait is 5 seconds again.
  - Each stop and each start is logged.
- **Visible members.** A member is visible while mDNS has found an endpoint whose id is the transport key of a device in the log that isn't revoked. The service compares against the log when asked, so a change to the log needs no rescan.
- Other OpenVault endpoints, from other vaults or joining devices, are never dialed.
- The service logs each member that becomes visible or stops being visible, by its name (membership.md, names key). Other OpenVault endpoints are logged only at debug level (`OPENVAULT_LOG=debug`).

## Local API

**The socket.**
- `service.sock` in the openvault directory, next to the vault (`~/.openvault/service.sock` unless `OPENVAULT_HOME` names another directory).
- The directory is mode 0700 and the socket 0600.
- A socket's path must fit in a socket address, about 100 bytes, so `OPENVAULT_HOME` can't be a deeply nested directory. A service that can't bind says so and exits, and commands then open the vault themselves.
- The service also checks that each connection comes from a process running as its own user, and closes it otherwise.
- On Windows, a named pipe comes later.

**Framing.** The same as sync.md: each message is `u32 length ‖ type ‖ body`, with the length covering the type and body. The limit is 16 MiB, so a folder of large values still fits. A connection carries one request and its response, and then closes.

**Fields.**
- `str`: `u16 length ‖ UTF-8`.
- `bytes`: `u32 length ‖ bytes`.
- `kind`: u8, the record kind (records.md): `0x01` secret, `0x02` var.
- Collections are named, not given by id.

### Requests

| Type | Request | Body |
| --- | --- | --- |
| `0x01` | collections | — |
| `0x02` | create collection | name (str) ‖ has phrase (u8) ‖ recovery phrase (str, only if has phrase is 1) |
| `0x03` | get | collection (str) ‖ name (str) |
| `0x04` | set | collection (str) ‖ count (u32) ‖ entries: name (str) ‖ kind ‖ value (bytes) |
| `0x05` | delete | collection (str) ‖ name (str) |
| `0x06` | list | collection (str) |
| `0x07` | folder | collection (str) ‖ folder (str) |
| `0x08` | devices | — |
| `0x09` | changed | — |
| `0x0a` | review | device id (16) |
| `0x0b` | revoke | device id (16) ‖ has phrase (u8) ‖ recovery phrase (str, only if has phrase is 1) |
| `0x0c` | set scope | device id (16) ‖ collection (str) ‖ scope (u8, as in membership.md) ‖ has phrase (u8) ‖ recovery phrase (str, only if has phrase is 1) |

- **set** writes every entry in one transaction, as `import-env` needs.
- **folder** returns the current values under `folder/`, for `openvault run`.
- **changed** says that something wrote to the vault without the service, as `approve` does. The service reloads what it keeps, as before every request, and starts sessions as after a log entry (sync.md, starting a session).
- **create collection** signs with this device's admin key when it has one, which asks for Touch ID. Otherwise it needs the recovery phrase. Without one in the request, it fails with "recovery phrase needed", and the CLI asks for the phrase and sends the request again.
- **review** returns what a device can read and what it wrote last, which `openvault devices revoke` shows before asking (sync.md, reviewing).
- **revoke** revokes a device (sync.md, revoking and reducing scopes). It signs like create collection, and starts sessions as after a log entry.
- **set scope** changes a device's scope on a collection, signed and followed by sessions in the same way. It fails before asking for a signature if the device already has that scope.

### Responses

| Type | Response | Body |
| --- | --- | --- |
| `0x80` | done | — |
| `0x81` | names | count (u32) ‖ names (str) |
| `0x82` | entry | found (u8) ‖ kind ‖ value (bytes), with kind and value only if found is 1 |
| `0x83` | entries | count (u32) ‖ entries: name (str) ‖ kind ‖ value (bytes) |
| `0x84` | listing | count (u32) ‖ entries: name (str) ‖ kind |
| `0x85` | deleted | existed (u8) |
| `0x86` | devices | count (u32) ‖ devices: id (16) ‖ flags (u8) ‖ platform (str) ‖ name (str) |
| `0x87` | review | count (u32) ‖ collections it reads: name (str) ‖ count (u32) ‖ secret names (str); then count (u32) ‖ collections: name (str) ‖ count (u32) ‖ entries it wrote last: name (str) ‖ deleted (u8) |
| `0x88` | revoked | count (u32) ‖ collections that got a new key (str) ‖ entries written again (u32) |
| `0x89` | scope set | new key (u8) ‖ keys granted (u32) ‖ entries written again (u32) |
| `0x7f` | error | code (u8) ‖ message (str) |

**Device flags.**

| Bit | Meaning |
| --- | --- |
| 0 | this device |
| 1 | revoked |
| 2 | visible on the local network |
| 3 | hardware keys (P-256) |

- A name that doesn't open, or breaks the name rules, comes back with an empty platform and name. The CLI then shows the device id instead (membership.md, names key).
- Error codes: `0x01` is any error, whose message the CLI prints. `0x02` is "recovery phrase needed".
- Buffers that hold values are wiped after use, on both sides.

## The CLI

- Every command except `init`, `service`, `join` and `approve` connects to the socket first. `join` and `approve` run their own endpoints (join.md, commands).
  - **If the service answers,** the command goes through it, and nothing asks for a passphrase.
  - **Otherwise,** the command opens the vault itself, as before. The service is optional, and `openvault run` still works on a device that doesn't run it.
- Both paths run the same request handler, so a command behaves the same either way.
- `openvault run` asks for the folder's values, then starts the command itself. The command doesn't inherit anything from the service.
- `openvault devices` lists the vault's devices: name, platform, key type, and whether each is this device, visible or revoked. Without the service, visibility is unknown, and the list says so.

## Cost

| Case | Cost |
| --- | --- |
| Idle | One mDNS query every 5 seconds or more, each answered by every OpenVault device on the network: a few hundred bytes of multicast. No connections and no database reads. |
| A command | One socket round trip, plus the same database reads as opening the vault directly, minus unlocking the keys. |
| A change by another process | One extra read of the membership state, on the next request. |
| mDNS that keeps stopping | A new lookup per wait: its sockets and one announcement. After the first few, at most one every 5 minutes. |

**What to watch once it runs:**
- mDNS packets per minute on the local network. They should stay flat as the vault grows.
- "mDNS discovery stopped" in the service's log. Once, at startup, is a socket that wasn't ready. Again and again is a socket that keeps failing, and the device is invisible most of the time.
- The service's resident memory. It holds one vault, the endpoint, and the 64 MiB Argon2id needs only while unlocking.

## Not in v1

- Starting at login (LaunchAgent, systemd user unit).
- Windows named pipes.
- The web UI on `localhost` (M4).
- Several vaults per device.
