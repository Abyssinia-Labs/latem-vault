# Service spec, v1

Status: draft, 2026-11-07. Changed 2026-11-09: starting at login, and the status request. Changed 2026-11-11: `--log`, the Mac app's LaunchAgent, and `parseEnv`. Implemented by `crates/net` (the endpoint and discovery), `crates/service` (the service and its local API) and `crates/cli` (starting at login). Builds on [records.md](records.md), [membership.md](membership.md) and [keystore.md](keystore.md). Sync ([sync.md](sync.md)) and joining ([join.md](join.md)) run inside it once they are built. The design is in [design §5](../design.md#5-architecture), [§10](../design.md#10-networking) and [§14](../design.md#14-interfaces).

`openvault service` is the one process on a device that holds the vault open. It:
- unlocks the device's keys once, so a passphrase is typed once per run rather than once per command;
- runs the device's iroh endpoint and finds the vault's other devices on the local network;
- answers the CLI over a local socket.

All integers are big-endian.

## Running it

- `openvault service` runs in the foreground and logs to stderr. It stops on Ctrl-C or SIGTERM, and removes its socket as it goes.
- `--log FILE` appends stdout and stderr to FILE instead, from before the vault is opened, so an error at startup lands there too. A leading `~/` is the home directory, for a LaunchAgent bundled in an app, which can't name it.
- It opens the vault as any command does: from the Secure Enclave, or after asking for the passphrase (keystore.md, passphrases).
- One service runs per vault. It holds a lock on `service.lock` in the openvault directory while it runs, and a second service that can't take the lock exits. The operating system drops the lock when a service crashes, so a socket found while holding it is left over, and is replaced.
- `openvault service install` has the operating system start it at login instead (below), and so does the Mac app, with a LaunchAgent of its own.

## Starting at login

`openvault service install` has the operating system start the service when the user logs in, and start it again if it stops. `openvault service uninstall` undoes that, and `openvault service status` says how things stand. It was written after the MacBook, the desktop and the mini each needed a definition written by hand to keep latem's builds working (design §18, progress).

**install**
- It refuses keys that need a passphrase, since nobody would be there to type it. It names two ways out: `openvault keys passphrase --remove` (keystore.md, changing the protection), or starting the service by hand.
- The definition runs the binary that `install` was run from, by its absolute path. A binary in a cargo `target` directory changes with each build, so `install` warns about one.
- `OPENVAULT_HOME`, when it's set, goes into the definition.
- It stops if a service is already running that the operating system didn't start, such as one in a terminal. That one has to be stopped first.
- Running it again is safe, and it's how a new build takes over: it writes the definition again and restarts the service.
- It then waits up to 10 seconds for the socket to answer, and says whether it did.

**macOS: a LaunchAgent.**
- `~/Library/LaunchAgents/local.openvault.service.plist`, with `RunAtLoad`, `KeepAlive` and a `ThrottleInterval` of 30 seconds.
- Output goes to `~/Library/Logs/openvault-service.log`.
- It's loaded with `launchctl bootout` and then `bootstrap`, in the `gui/<uid>` domain. macOS can load a new file in that directory by itself, so a definition that's already loaded is restarted with `launchctl kickstart -k` instead.
- macOS then shows a "Background Items Added" notice. It also asks, once, whether openvault may use the local network, and, with the firewall on, whether it may accept incoming connections.
- A binary built with cargo is signed ad hoc, and macOS asks again for each new build. Until someone answers, mDNS stops and starts again (discovery).

**Linux: a systemd user unit.**
- `$XDG_CONFIG_HOME/systemd/user/openvault.service`, or `~/.config/systemd/user/openvault.service`, with `Restart=on-failure` and `RestartSec=30`, after `network-online.target`.
- `install` runs `systemctl --user daemon-reload`, `enable` and `restart`.
- Output goes to the journal: `journalctl --user -u openvault`.
- Without lingering, a user's units start at login rather than at boot. `install` says so and shows `loginctl enable-linger <user>`. It doesn't run it, because it changes how the system starts.
- Without a systemd user instance, as in some WSL setups, `install` fails and says so.

**uninstall** stops the service and removes the definition. The vault is untouched.

**The Mac app** bundles this binary and starts it with a LaunchAgent of its own, in place of `install`'s (M5, `openvault-apple`):
- The agent, `com.abyssinialabs.openvault.service`, is in the app bundle and registered with `SMAppService`. It runs `Contents/Helpers/openvault service --log ~/Library/Logs/openvault-service.log`, with `RunAtLoad`, `KeepAlive` and a `ThrottleInterval` of 30 seconds, as `install`'s does.
- The app registers it only for a vault whose keys need no passphrase. It asks the library first (`deviceHome`: whether there's a vault, and how its keys are kept).
- Before registering, it runs the bundled `openvault service uninstall` if `install`'s definition is there, so that two agents don't start two services for one vault.
- The binary is signed with the app's Developer ID, so macOS keeps one answer to its local network question across builds.
- The CLI knows the app's agent by its label. While launchd has it loaded, `install` refuses and names the switch in Login Items that turns it off. `status` says the app starts the service, and that updating the app moves it onto a new build. `uninstall` says the app starts it rather than that nothing was installed.

**status** says:
- whether a definition is installed, and where;
- whether launchd or systemd has the service running, and its process id;
- whether the socket answers; if it does, the running service's version next to this binary's, and how many times mDNS has stopped since it started.

**The store.** The service keeps one connection to the store and handles requests one at a time. Before each request it checks SQLite's `data_version`, which changes when another process has written. If it has changed, the service reloads the membership it keeps in memory. A command run while the service starts up, before the socket is there, therefore can't leave the service with a stale log.

## Endpoint

Each device runs one iroh endpoint (design §10):

- **Identity.** Its secret key is the transport key (records.md, local store), so its endpoint id is the transport key in the device's add_device entry.
- **Relays.** It never connects to n0's relays. With a coordinator configured, and built with the `coordinator` feature, it uses the grandfather's relay and no other (coordinator.md, devices); otherwise no relay at all.
- **No publishing.** It uses no DNS or pkarr address lookup and no port mapping. Without a coordinator, nothing outside the local network learns the endpoint id or addresses; with one, the grandfather does.
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
| `0x0d` | status | — |

- **set** writes every entry in one transaction, as `import-env` needs.
- **folder** returns the current values under `folder/`, for `openvault run`.
- **changed** says that something wrote to the vault without the service, as `approve` does. The service reloads what it keeps, as before every request, and starts sessions as after a log entry (sync.md, starting a session).
- **create collection** signs with this device's admin key when it has one, which asks for Touch ID. Otherwise it needs the recovery phrase. Without one in the request, it fails with "recovery phrase needed", and the CLI asks for the phrase and sends the request again.
- **review** returns what a device can read and what it wrote last, which `openvault devices revoke` shows before asking (sync.md, reviewing).
- **revoke** revokes a device (sync.md, revoking and reducing scopes). It signs like create collection, and starts sessions as after a log entry.
- **set scope** changes a device's scope on a collection, signed and followed by sessions in the same way. It fails before asking for a signature if the device already has that scope.
- **status** returns the service's version, its process id, and how many times mDNS has stopped since it started (discovery). Only the service answers it. A service older than 0.2.2 answers with an error, which `openvault service status` reports as an older build.

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
| `0x8a` | status | version (str) ‖ process id (u32) ‖ mDNS stops (u32) |
| `0x7f` | error | code (u8) ‖ message (str) |

**Device flags.**

| Bit | Meaning |
| --- | --- |
| 0 | this device |
| 1 | revoked |
| 2 | visible on the local network |
| 3 | hardware keys (P-256) |

- A name that doesn't open, or breaks the name rules, comes back with an empty platform and name. The CLI then shows the device id instead (membership.md, names key).
- Error codes: `0x01` is any error, whose message the CLI prints. `0x02` is "recovery phrase needed". `0x03` is "wrong code" (for apps, below).
- Buffers that hold values are wiped after use, on both sides.

### For apps

Since 0.3.3, for the Mac app (design §12), which reaches the service through the Swift bindings in `crates/ffi` (`scripts/swift-bindings.sh` builds them). The CLI and the service come from the same release, so the local API has no version of its own: an older service answers these with error "unknown request" until `openvault service install` restarts it on the new build.

| Type | Request | Body |
| --- | --- | --- |
| `0x0e` | vault | — |
| `0x0f` | collection summaries | — |
| `0x10` | entry details | collection (str) |
| `0x11` | log | from seq (u64) ‖ max (u16) |
| `0x12` | set scopes | device id (16) ‖ count (u32) ‖ changes: collection (str) ‖ scope (u8) ‖ has phrase (u8) ‖ recovery phrase (str, only if has phrase is 1) |
| `0x13` | watch | — |
| `0x14` | peers | — |
| `0x15` | joiners | — |
| `0x16` | check code | endpoint id (32) ‖ code (str) |
| `0x17` | approve | session (u32) ‖ count (u32) ‖ scopes: collection (str) ‖ scope (u8) ‖ has phrase (u8) ‖ recovery phrase (str, only if has phrase is 1) |
| `0x18` | refuse | session (u32) |

| Type | Response | Body |
| --- | --- | --- |
| `0x8b` | vault | vault id (16) ‖ device id (16) ‖ recovery fingerprint (4) ‖ log head (u64) ‖ admin (u8) |
| `0x8c` | collection summaries | count (u32) ‖ collections: name (str) ‖ secrets (u32) ‖ variables (u32) ‖ key (u32) ‖ count (u32) ‖ devices: device id (16) ‖ scope (u8) |
| `0x8d` | entry details | count (u32) ‖ entries: name (str) ‖ kind ‖ set by (16) ‖ key (u32) ‖ value (bytes) |
| `0x8e` | log | count (u32) ‖ entries: seq (u64) ‖ hash (32) ‖ change (u8) ‖ device id (16) ‖ collection (str) ‖ scope (u8) ‖ key (u32) ‖ signer (u8) |
| `0x8f` | event | what (u8) ‖ count (u32) ‖ collections (str) |
| `0x90` | peers | count (u32) ‖ peers: device id (16) ‖ state (u8) ‖ seen (u32) ‖ retry in (u32) ‖ error (str) |
| `0x91` | joiners | count (u32) ‖ joiners: endpoint id (32) ‖ platform (str) ‖ name (str) |
| `0x92` | join request | session (u32) ‖ device id (16) ‖ platform (str) ‖ name (str) ‖ hardware (u8) |
| `0x93` | scopes set | count (u32) ‖ collections that got a new key (str) ‖ keys granted (u32) ‖ entries written again (u32) |

**Reads.**
- **vault**: the recovery fingerprint is the first 4 bytes of the hash of the recovery key, shown as `d06a 5f28`. The log head is the last entry's seq, 0 before the log starts. Admin is 1 when this device has an admin key the log lists.
- **collection summaries**: every collection on this device, with its counts of secrets and variables, its current key (epoch), and each device that isn't revoked and has a scope on it other than none. Counting reads only the index, as list does.
- **entry details**: every current entry of a collection, with the device that set it and the key it was sealed with. Variables come with their values; a secret's value is always empty, so a list never holds one. It opens every record, so a collection of n entries costs n decryptions.
- **log**: up to `max` entries from seq `from`, at most 256 at a time. Change is the entry's type (membership.md): device id, collection, scope and key are filled in where the type has them, and zeros or empty otherwise. A collection is given by name, or by its id in hex if this device doesn't have it. Signer: `0x00` the recovery key, `0x01` this device's admin key, `0x02` another admin key. The log keeps no times, so neither does this.
- **peers**: only the service answers it. For each member other than this device: state `0x00` not seen since the service started, `0x01` on the network, `0x02` syncing, `0x03` its last session failed; seen is seconds since mDNS last showed it (0 while it's on the network, `0xffffffff` never); retry in is seconds until the next attempt after a failure (0 if none is waiting); error is why the last session failed, or empty.

**Scopes.** set scopes makes several scope changes for one device with one admin signature, so Touch ID asks once. It fails before asking if every change is to the scope the device already has, and skips the ones that are. The changes are made in order, each with its own log entry; if one fails, the ones before it stay. scopes set lists the collections that got a new key, and adds up the keys granted and the entries written again.

**Watch.** The service answers with done and keeps the connection open. It then sends an event whenever something an app shows may have changed, and the client sends nothing more; closing the connection ends the watch.
- What is a set of bits: `0x01` entries changed, in the collections listed, or in any of them if none are listed; `0x02` the membership log changed; `0x04` a device came or went, or its sync state changed; `0x08` a device started or stopped waiting to join.
- Events come from this device's own writes, from sync sessions that took something in, from mDNS, and from join sessions. There's no polling, so an idle watch costs nothing.
- At most 16 connections watch at once; another gets an error.

**Joins.** Only the service answers these, since they use its endpoint (join.md).
- **joiners** lists the endpoints whose mDNS announcement says they're waiting to join, with the platform and name they announce. The announcement is unchecked, as join.md says.
- **check code** runs the PAKE with a joiner (join.md, the admin's side). With the right code it answers with a join request: the session that holds it, and the device id, platform, name and key type the joiner signed. With a wrong code it answers with error `0x03`, whose message says how many tries are left; after three the joiner stops, and the service refuses more codes for it until it announces again.
- **approve** approves the session's request with the scopes given, signed like revoke: with this device's admin key, which asks for Touch ID, or with the recovery phrase. It then sends the joiner the log and grants, and starts sessions as after a log entry.
- **refuse** tells the joiner it wasn't approved, and ends the session.
- A session ends after approve or refuse, when the joiner goes away, or after 10 minutes, the code's lifetime. At most 4 are open at once.
- `openvault approve` uses these when the service runs, and its own endpoint otherwise.

**Without the service.** The bindings also read two things themselves:
- `deviceHome` (0.3.4) says whether an openvault directory holds a vault, and how its keys are kept.
- `parseEnv` (0.3.5) reads a `.env` file with `import-env`'s parser, which is in `openvault-core` for that reason. An app's import then reads each file the same way the CLI and latem do. The parser refuses a NUL byte in a value, which no environment variable can hold.

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

- Starting at login on Windows, and starting at boot without lingering on Linux.
- Windows named pipes.
- The web UI on `localhost` (M4).
- Several vaults per device.
