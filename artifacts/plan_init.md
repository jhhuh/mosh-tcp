# Plan: mosh-tcp — Mosh over TCP with length-prefixed framing

## Background

Mosh uses UDP datagrams for its SSP (State Synchronization Protocol). In many
corporate/restricted networks, UDP is blocked. Tailscale's DERP relay solves a
similar problem by embedding UDP-like datagrams inside TCP using a simple
**length-prefixed framing** protocol: `[4-byte big-endian length][payload]`.

Mosh's SSP is idempotent/stateless — it always sends the latest state, never
retransmits — so the classic "TCP-over-TCP meltdown" is not a concern here.

## Architecture: What changes

Only **one file** contains raw socket syscalls: `src/network/network.cc`.
Everything above it (`Transport`, `TransportSender`, `FragmentAssembly`, `Crypto`,
`Protobuf`, `StateSync`) deals with complete string payloads and needs **zero changes**.

### Framing protocol (DERP-lite)

```
[uint32_t big-endian: payload length][payload bytes]
```

- No type byte needed (mosh has only one message type at the wire level)
- Max payload: 65536 bytes (matches mosh's `MaxPacketSize`)
- This is identical to DNS-over-TCP (RFC 1035 §4.2.2) but with 4-byte length

### What we lose (acceptable)

- **Port hopping**: TCP is connection-oriented; removed entirely
- **Client roaming**: TCP connection breaks on IP change; in environments
  where UDP is blocked (corporate firewalls), roaming is unlikely
- **ECN/congestion signals**: TCP handles its own congestion control

## Steps

### Step 1: Project init
- Init git repo at `/home/jhhuh/Sync/proj/mosh-tcp`
- Add mosh upstream as a remote, fetch, and create our branch from `mosh-1.4.0` tag (latest release)
- Create nix flake with devShell (autotools, protobuf, zlib, openssl, ncurses, pkg-config)
- Verify upstream builds from source

### Step 2: Modify `src/network/network.h`
- `Socket` constructor: `SOCK_DGRAM` → `SOCK_STREAM`
- Remove port-hopping constants (`PORT_HOP_INTERVAL`, `MAX_PORTS_OPEN`, `MAX_OLD_SOCKET_AGE`)
- Add read buffer for TCP framing (partial read accumulation)
- Add `listen_fd` member for server accept model
- Increase `DEFAULT_SEND_MTU` to 16384 (avoid unnecessary fragmentation over TCP)
- Update string constants ("UDP" → "TCP")

### Step 3: Modify `src/network/network.cc` (core change)
- **Socket constructor**: `SOCK_DGRAM` → `SOCK_STREAM`, remove `IP_PMTUDISC_DONT`/`IP_TOS`/`IP_RECVTOS`
- **Server bind** (`try_bind`): `SOCK_DGRAM` → `SOCK_STREAM`, add `listen()`, set `SO_REUSEADDR`
- **Server constructor**: after bind, `accept()` one connection (blocking, with timeout via select)
- **Client constructor**: `SOCK_DGRAM` → `SOCK_STREAM`, add explicit `connect()`
- **`send()`**: replace `sendto()` with `[4-byte length prefix][payload]` write via `writev()`
- **`recv_one()`**: replace `recvmsg()` with buffered read: read 4-byte length, then read exactly N bytes. Handle partial reads (`EAGAIN`).
- **Delete** `hop_port()`, `prune_sockets()`
- **Simplify** `fds()`: always returns exactly 1 fd
- **`port()`**: remove `NI_DGRAM` flag

### Step 4: Modify frontends (minor)
- `src/frontend/mosh-server.cc`: server accept logic before entering serve loop; simplify fd assert
- `src/frontend/stmclient.cc`: simplify fd_list loop (always 1 fd); update "UDP port" strings
- `src/frontend/stmclient.h`: update error message strings
- `src/frontend/mosh-client.cc`: update "Bad UDP port" string

### Step 5: Update `scripts/mosh.pl` wrapper
- Default port range can stay the same (60001-60999)
- Update help text to say TCP instead of UDP
- SSH command that starts mosh-server remains the same (just port forwarding changes)

### Step 6: Build & smoke test
- `./autogen.sh && ./configure && make`
- Run `mosh-server` locally, connect with `mosh-client` via TCP
- Verify basic terminal interaction works

## Files changed (ordered by importance)

| File | Change scope |
|------|-------------|
| `src/network/network.cc` | Major: all socket ops, framing, accept/connect |
| `src/network/network.h` | Medium: constants, Socket class, read buffer |
| `src/frontend/mosh-server.cc` | Minor: accept() before serve loop |
| `src/frontend/stmclient.cc` | Minor: fd simplification, strings |
| `src/frontend/stmclient.h` | Trivial: error message string |
| `src/frontend/mosh-client.cc` | Trivial: error message string |
| `scripts/mosh.pl` | Minor: help text |
| `flake.nix` | New: nix build environment |

## Files NOT changed

- `src/crypto/*` — encryption above transport
- `src/network/transportfragment.*` — fragment encoding (kept as-is, just larger MTU)
- `src/network/networktransport*` — transport layer (receives complete strings)
- `src/network/transportsender*` — sender logic (unchanged except effective MTU)
- `src/protobufs/*` — protocol buffers
- `src/statesync/*` — state sync
- `src/terminal/*` — terminal emulator
