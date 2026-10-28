# Changelog

## parley-dns 2.0.0 (unreleased)

### Added

- **`$INHERIT zone`** in a zone file: the zone serves the records of another zone (the primary domain's) too,
  renamed into it, and its own records add to them or override them by name and type. Updates change the
  zone's own records; a change to the primary reaches every zone that inherits from it. See the README.
- **JMX**: `us.bringardner.parley:type=Dns,name=…` (`DnsServerMXBean`): state, the zones (own and inherited
  serials and records), each zone's records marked own or inherited, load errors, reload, and making an
  inheriting zone for a new domain. `DnsServer.main` registers it on the platform MBean server.
- **`DnsServerProvider`**: `dns` in parley-net's launcher (`parley.servers`), so DNS runs and is managed
  like every Parley server (`us.bringardner.parley:type=Server,name=dns`), with its `Dns` bean while it runs.

### Changed

- **`DnsServer.main` runs the server as a service** with parley-net's `ServerMain.run`: settings from the command
  line (which wins) and `parley-dns.properties` in Parley's administrator folder (`/etc/parley`, or the file the server's
  `configFile` property names); it stops on SIGTERM; with its fatal-error handler as before; a failed start exits with 1 (was -1 or -2).

### Changed (needs a configuration change)

- **Property names** (Parley 2.0.0; the old names are no longer read): `JDns.*` is `parley.dns.*`. Most keep
  the rest of their name; `JDns.dnsPort` is `parley.dns.port`, `JDns.master.zone` `parley.dns.masterZone`,
  `JDns.zone.dir` `parley.dns.zoneDir`, `JDns.udp.bindAddress` `parley.dns.udpBindAddress`, `JDns.dump.file`
  `parley.dns.udpDumpFile`, `JDns.ra` `parley.dns.recursionAvailable`, `JDns.jdbcURL` / `JDns.jdbcClass`
  `parley.dns.jdbcUrl` / `parley.dns.jdbcDriver`, `JDns.useDataBase` `parley.dns.useDatabase`, `JDns.properties`
  `parley.dns.configFile`, and the default config file `JDns.properties` is `parley-dns.properties`, and NsLookup's `echoCommand`
  `parley.dns.nslookup.echoCommand`. See the README's table.
- The names 1.0.0 still read with a warning (`UDPProcCount`, `TCPProcCount`, `Resolver.maxBacklog`, and
  `name` / `port` for DnsAdminClient) are no longer read.
- The admin server's prefix is `parley.dns.admin`, the TCP listener's `parley.dns.tcp`.

## parley-dns 1.0.0 (2026-10-16)

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
- Round 4 #65: answers to TSIG-signed recursive queries are signed (the resolver thread used to
  send them unsigned, so the client rejected them).
- Round 4 #62: upstream servers that answer REFUSED or NOTAUTH, or refer upwards or sideways (lame),
  count as failing for ranking (SERVFAIL, NOTIMP and FORMERR can be about one name and don't); when only such referrals come back the
  client gets SERVFAIL instead of NOERROR without data.
- Round 4 #64: records an upstream server gives for names outside its zone are dropped (a server
  for evil.example can no longer add an address for www.bank.example after a CNAME to it); a CNAME
  chain that ends without the data is followed by asking the target's own servers. Records from the
  root hints' servers (which may be a recursive upstream) are not filtered; out-of-zone glue is
  dropped, so such name servers are looked up separately.
- Round 4 #69: UDP requests up to 64 KB are read whole (larger than 2 KB were cut off); upstream
  answers already were.
- Packaging: the POM takes plugin versions and `distributionManagement` from parley-parent (the old
  source, deploy, surefire and site plugin overrides are gone; the sources jar is built once);
  `nsupdate` / `nslookup` say parley-dns instead of BjlDns; the stale `Readme.txt` is removed.
- Round 5 #84: the UPDATE journal is crash safe: the header is written into an empty journal too,
  each update is framed by `begin`/`end` lines (a torn last update is left out on replay), and a
  failed write is cut off again. Older journals without the framing still replay.
- Round 5 #88: a signed zone that can't be signed again keeps serving its last signed version while
  the signatures are valid (also after its zone file changed), instead of going unsigned; an UPDATE
  or re-sign that can't be signed is not made (nothing journaled).
- Round 5 #89: SHA-1 DS records are ignored when a SHA-256 or SHA-384 one is there (RFC 4509 3).
- Round 5 #90: DNSKEYs with the REVOKE bit (RFC 5011) are not used to validate.
- Round 5 #91, denial proofs: NSEC3 records with unknown flags are ignored (RFC 5155 8.2); a DNAME
  owner, like a delegation, proves nothing below it (RFC 6840 4.1); an NSEC whose next name is below
  the query name can't prove NXDOMAIN (the name exists); an NSEC3 closest encloser that is a
  delegation or DNAME is refused.
- Round 5 #92: SECURE answers in the cache, and validated key sets, are kept no longer than their
  signatures allow (original TTL, expiration; RFC 4035 5.3.3), and served TTLs are capped to match.
- Round 5 #97: an OPT record in the answer or authority section is FORMERR (RFC 6891 6.1.1).
- Round 5 #98: an UPDATE with a newer SOA replaces the whole SOA (names, timers, TTL), not only its
  serial (RFC 2136 3.4.2.2); the journal has a new `soa` entry for it.
- Round 5 #99: a NOTIFY answered with an error is not counted as acknowledged: REFUSED, NOTAUTH and
  the like are logged and not retried (`ZoneNotifier.getRefused()`); SERVFAIL is retried.
- Round 5 #100: a TSIG MAC longer than the hash, or shorter than the larger of 10 bytes and half of
  it, is FORMERR (RFC 8945 5.2.2.1); it was answered BADSIG / BADTRUNC.
- SSHFP (RFC 4255, 6594): the `Sshfp` record (zone files, UPDATE, wire), `SshfpVerifier` to check an SSH
  host key against validated SSHFP records, and `SshfpTool` to print the records for host keys.
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

- `us.bringardner.parley.dns.server.AddressMatcher`: use `us.bringardner.parley.core.util.AddressMatcher`
  (parley-core), which it only wrapped.
- `ByteBuffer.chkPointer()` (no protection against pointer loops; name parsing follows
  pointers itself), `ByteBuffer.getInc()` / `setInc(int)` (the buffer grows by doubling) and
  `ResolverThread.notifyThreads()` (did nothing).
- `us.bringardner.parley.dns.dynamic.DynamicDns`. Nothing in the library used it, and when its
  `JDns.jdbc*` properties were missing it fell back to a built-in database host and login.
  Dynamic records are kept by `DnsServer` (`dynamic.txt` or the `JDns.jdbc*` database).
