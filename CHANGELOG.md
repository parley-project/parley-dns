# Changelog

## parley-dns 1.0.0 (unreleased)

BjlDns is now **parley-dns**, part of the Parley library family. The code is the same as
BjlDns 1.0.1-SNAPSHOT; only names changed.

### Changed (needs a code change)

- Maven coordinates: `us.bringardner:bjl_dns` is now `us.bringardner.parley:parley-dns`.
- Packages: `us.bringardner.net.dns` (and `.dnssec`, `.dynamic`, `.resolve`, `.server`, `.util`)
  is now `us.bringardner.parley.dns`. Command lines that name a class change too, for example
  `us.bringardner.parley.dns.server.DnsServer` and `us.bringardner.parley.dns.util.NsLookup`.
- Module name (`Automatic-Module-Name`): `us.bringardner.parley.dns` (none was set before).
- Dependencies: `bjl_core` and `bjl_io` are now `parley-core` and `parley-io`.
- The `JDns.*` configuration properties are unchanged.

### Changed (redesign: parley-dns on the Parley framework)

- parley-dns now depends on **parley-net**. The admin port runs on parley-net's `Server`
  (`DnsAdminServer`, with a `DnsAdminProcessor` per session) and `DnsAdminClient` on its `Client`.
  The admin protocol, properties and replies are unchanged. Each session has its own commands: a
  command's output used to go to the newest connection, logged in or not.
- Zone reloads, dynamic records and re-signing run on their own thread (`DnsMaintenance`), each
  step guarded: an error is logged and the next round goes ahead. They used to run in the admin
  accept loop, where one RuntimeException stopped them for good.
- `FatalErrorHandler` moved to parley-net (`us.bringardner.parley.net.FatalErrorHandler`);
  `JDns.exitOnFatalError` is now `DnsServer.PROP_EXIT_ON_FATAL_ERROR`.
- Removed: `DnsServer.handleAdminConnection` and `createAdminSocket` (use `startAdminServer(port)` /
  `createAdminServer(port)`), and the old `DnsAdminProcessor` constructor `(DnsServer, Socket)`.
- DNS over TCP runs on parley-net's `NioServer` (2-byte `LengthFieldFrameDecoder`): no thread per
  connection; requests are answered on a pool of up to `JDns.tcpMaxConnections` handler threads,
  one at a time per connection. `TCPProsessor`'s static API is unchanged (plus an `initTCPProsessor`
  overload with the per-client limit and reactor count, and `closeListener()`).
  - Round 5 #78: a message that has started must arrive within `JDns.tcpIdleTimeout`; a client
    sending a byte now and then can no longer hold a connection slot.
  - Round 5 #72: new `JDns.tcpMaxConnectionsPerClient` (default 8): one address can't take every
    connection slot.
  - `JDns.tcpProcCount` is now the number of reactor threads; `JDns.tcpTimeout` is no longer used
    for TCP.
  - A client that stops reading a large answer (a zone transfer) is disconnected after the idle
    timeout instead of holding a handler thread.
- `ByteBuffer` is built on parley-io's `WireBuffer`: every read is bounds checked (FORMERR, not an
  exception from the array), and each type's rdata is read through `RR.rdataReader()`, limited to its
  RDLENGTH and required to use all of it (`RR.endOfRdata`). Round 5 fixes:
  - #79: a record whose rdata is shorter or longer than its content is a format error (an MX with
    RDLENGTH 2 used to take its exchange from the next record).
  - #80: compression pointers only point below offset 0x3FFF (names past 16 KiB were corrupted).
  - #81: names are written as ISO-8859-1, as they are read (a label with a high byte was echoed as
    UTF-8 with the wrong length).
  - #82: names in text form use master-file escapes (`\.` inside a label, `\\`, `\DDD`); a label over
    63 octets, an empty label or a name over 255 octets is refused when written instead of corrupting
    the message. `Name.wireLabels`, `Name.escapeLabel`, `ByteBuffer.setName(name, compress)`,
    `setNameAsIs`.
  - #93: canonical form (`Canonical.key`, signing) lower-cases A-Z only (RFC 4034 6.2);
    `Canonical.isBelow` compares labels.
  - #95: A and AAAA rdata must be 4 and 16 bytes; `Section.toString` prints any type or class
    (CLASS254 is NONE, TYPEnnn / CLASSnnn otherwise).
  - #96: RP and AFSDB names are written without compression (RFC 3597 4).
  - `setRdLength` refuses rdata over 65535 bytes; `setRdata` forgets the message the record came from.
- DNSSEC keys use parley-core's crypto helpers (`Ec`, `PrivateKeys`):
  - ECDSA DNSKEYs must be points on the curve; a key that isn't verifies nothing (it used to be
    handed to the JDK as is). Signatures convert between DER and r||s with bounds-checked parsing.
  - Round 5 #94: a new `.private` file is created with `PrivateKeys.writePrivateFile` (new file only,
    so an existing file or symlink is refused; owner-only from the start). Loading a `.private` file
    that its group or everyone can read logs a warning.
- Resolver (round 4 #58, #59, #70):
  - The recursive query queue is an `ArrayBlockingQueue` (one thread woken per query, not all of
    them); `SimpleObjectFIFO` is removed.
  - A queued query older than `JDns.resolverMaxQueueAge` (default 3000 ms) is dropped instead of
    resolved: its client has given up (`ResolverThread.getStale()`).
  - Identical lookups (name, type, class, CD) share one upstream resolution: later askers wait without
    holding a thread and are answered from the cache it fills (`ResolverThread.getCoalesced()`).
  - Resolver threads are virtual threads on Java 21+ (`JDns.resolverVirtualThreads`, default true).
  - Upstream address ranking and hold-off moved to parley-net's `UpstreamHealth`; `ServerA` keeps its
    settings and methods.
- `Base32Hex` and `RenamedProperty` moved to parley-core (`us.bringardner.parley.core.util`); a
  deprecated property name is now logged as a warning rather than an error.

### Changed (behaviour)

- Unsigned dynamic updates allowed by address (`JDns.updateAllow`) are accepted over UDP only from
  this machine (loopback). From other addresses, send them over TCP (`nsupdate -v`) or sign them
  with a key in `JDns.updateKeys`: a UDP source address can be forged.
- A signed UPDATE or zone transfer request is acted on once. The same UPDATE again gets the first
  answer without being applied again; the same transfer request again gets NOTAUTH (BADTIME).
- An UPDATE is REFUSED when one of its changes can't be written to the journal and read back
  unchanged (e.g. a name containing a space).
- A DNSSEC-validated (SECURE) answer carries only the records that were validated.
- PTR targets are written to the dynamic update journal (`<zone>.jnl`) as absolute names. Journals
  written before this kept them without the final dot, and replaying them turned a target such as
  `host.example.` into `host.example.<zone>.`: check PTR records added by dynamic update, or set
  the old journal aside (raise the zone file's serial) once the zone file is up to date.

### Removed

- `us.bringardner.parley.dns.dynamic.DynamicDns`. Nothing in the library used it, and when its
  `JDns.jdbc*` properties were missing it fell back to a built-in database host and login.
  Dynamic records are kept by `DnsServer` (`dynamic.txt` or the `JDns.jdbc*` database).
