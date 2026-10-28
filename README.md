# parley-dns

> parley-dns is part of **Parley**, a family of Java libraries for implementing internet protocols.
> It was previously `us.bringardner:bjl_dns` (BjlDns), with packages under `us.bringardner.net.dns`.
> Moving over means changing the dependency and replacing `us.bringardner.net.dns` with
> `us.bringardner.parley.dns` in imports and in class names on the command line.
> Configuration properties (`parley.dns.*`) are unchanged.

```xml
<dependency>
    <groupId>us.bringardner.parley</groupId>
    <artifactId>parley-dns</artifactId>
    <version>1.0.0</version>
</dependency>
```
 The DNS project provides everything you need to run a DNS server and  a DNS client
 and the NsLookup and NsUpdate tools (work-alikes of nslookup and nsupdate).

The intent of this DNS code is to support a large number of domains with very little administrative overhead.
 

 
# Major Features:
 +  Supports unique configuration for any domain.
 +  Supports a common configuration that will be used for any domain that does not have a unique configuration.
 +  Domains may be in a database or file system
 +  Support Dynamic DNS (DDNS) with trivial configuration
 +  Zone file record types: SOA, NS, A, AAAA, CNAME, PTR, MX, TXT, SPF, HINFO, RP, SRV, CAA, HTTPS, SVCB, DS (other types are passed through unchanged when resolving)
 +  DNSSEC: zones are signed by the server itself when it has keys for them, or served as signed by another tool (see below)

Not supported: incremental zone transfer (IXFR is answered with the whole zone), acting as a secondary (incoming NOTIFY gets NOTIMP), signing with NSEC3 opt-out (zones signed elsewhere with it are served), automatic trust anchor updates (RFC 5011), and the `$GENERATE` zone file directive.

# Zone files

Each `<zone>.txt` file in `parley.dns.zoneDir` is one zone, in the RFC 1035 master file format:

 +  `$ORIGIN name` sets the origin for relative names and `@` (a relative `$ORIGIN` is relative to the current one). Before the SOA it also names the zone; otherwise the zone is named after the file.
 +  `$TTL ttl` (RFC 2308) is the TTL for the records after it that don't give one. Without `$TTL`, such records get the SOA's TTL, and an SOA without a TTL gets its MINIMUM. A TTL written on a record is used as is.
 +  `$INCLUDE file [origin]` reads another file at that point; a relative path is relative to the including file, and the origin is restored afterwards. Includes can be nested (up to 10 levels; loops are rejected). Name included files something other than `*.txt` (e.g. `hosts.inc`), or they will be loaded as zones of their own. Editing an included file reloads the zone.
 +  HTTPS and SVCB (RFC 9460): `@ IN HTTPS 1 . alpn=h2,h3 port=8443 ipv4hint=192.0.2.1` (ServiceMode; `.` means the owner name) or `www IN HTTPS 0 cdn.example.net.` (AliasMode, no parameters). Keys: `mandatory`, `alpn`, `no-default-alpn`, `port`, `ipv4hint`, `ech` (base64), `ipv6hint` and `keyNNNNN="value"`. Invalid combinations (parameters in AliasMode, a `mandatory` key that is missing, `no-default-alpn` without `alpn`, a key given twice) stop the zone from loading. In answers, the server adds the addresses (A/AAAA) of the target to the additional section when the target is in one of its zones, and for AliasMode also the target's own HTTPS/SVCB records (RFC 9460 4.2).
 +  TXT and SPF: each quoted string (or unquoted word) is a separate string, e.g. `@ IN TXT "v=DKIM1; k=rsa; " "p=MIIB..."`; a string longer than 255 bytes is split. Inside quotes `\"`, `\\` and `\DDD` (a byte in decimal) are escapes, and the text is UTF-8.
 +  TTLs can use units: `300`, `30m`, `1h30m`, `2d`, `1w`.
 +  Parentheses can span lines anywhere in a record, and `;` starts a comment except inside quotes.
 +  A zone file that fails to load is reported with the file name and line number (and the previous version keeps being served).

# Inherited zones ($INHERIT)

A domain can serve the records of another zone, the primary domain's, so many domains share one set of
records: `$INHERIT bringardner.us.` in `example.com.txt` (in the zone file itself, once; the file still needs its
own SOA).

 +  Every record of the primary is served in the domain under the same relative name: the primary's `www`
    is `www.example.com`, its apex MX is example.com's MX. The record data is copied as written, so names in
    it (an MX's mail server, a CNAME's target) still point at the primary's hosts.
 +  The domain's own records add to them, or override them by name and type: an own MX replaces the
    inherited MX, and an own TXT at a name replaces every inherited TXT there. An own CNAME hides everything
    inherited at its name, and an inherited CNAME is left out where the domain has records of its own.
 +  The primary's SOA and DNSSEC records are not inherited. The SOA served is the domain's, with the sum of
    the two serials, so it goes up when either zone changes and secondaries transfer the domain again.
 +  An inherited NS record below the apex (a delegation) is left out where the domain has records of its
    own at or below its name, so it doesn't send them elsewhere.
 +  Dynamic updates of the domain change its own records (and its journal); an update or edit of the
    primary reaches every domain that inherits from it. Only one level: a primary can't inherit itself.
    An update sees only the domain's own records: deleting an inherited record changes nothing (override
    it with a record of its own instead), a prerequisite on an inherited record fails, and an SOA
    prerequisite compares the domain's own serial.
 +  When the primary isn't served (its file removed or broken), the domain keeps serving what it served
    with it; at a start without the primary it serves only its own records. A serial that goes down (the
    `$INHERIT` line removed, say) is logged: raise the zone file's serial above the one served.
 +  Inheriting zones are not signed (DNSSEC keys for them are not used).

# Mail domains (parley.dns.mailSettings)

With `parley.dns.mailSettings` naming the mail servers' shared settings (the mail queue's `queue.properties`,
which parley-mail-admin's Domains page edits), the mail domains need no zone files:

 +  Each domain in its `domains` that has no zone of its own is served as a zone inheriting from
    `parley.dns.masterZone` (as with `$INHERIT` above, with an SOA like the master's, serial 1), made in memory.
    A domain added there is served within the maintenance round; one removed is no longer served.
 +  Its zone file is written only when one of its records is changed (a dynamic update, e.g. from
    parley-mail-admin's DNS page), so the change can be journaled beside it; from then on it is a zone with a
    file, its own records overriding the master's, and it stays served if the domain leaves the list.
    Writing it is refused while an old journal of that zone is there.
 +  Each key in its `dkim.keys` (`domain:selector:keyfile`) is served at `selector._domainkey.domain`, from
    the record text parley-mail-admin keeps beside the key (`keyfile.txt`), or made from the key itself
    (an RSA key in PKCS#8 PEM), unless the zone has records at that name. A new key is served once the
    settings or the key's files change.
 +  The master zone answers `domain._report._dmarc.master` with `v=DMARC1` for each listed domain outside
    the master's own (RFC 7489 7.1), so the reports an inherited DMARC record asks for, at an address in the
    master domain, are sent.
 +  Problems (a name that isn't a domain, a key that can't be read) are logged and reported with the zone
    errors (JMX `getErrors`); the rest is served.
 +  These records are not part of zone transfers: a secondary gets the zones' own and inherited records.

# Management (JMX)

`us.bringardner.parley:type=Dns,name=…` (`DnsServerMXBean`, an MXBean any JMX client can read) gives the
server's state, its zones (inherited from, served and own serials, record counts, signed), a zone's records
marked own or inherited, the zone files that failed to load, `reload()`, and `createInheritingZone(domain, primary)`,
which writes the domain's zone file (an `$INHERIT` line and an SOA like the primary's) and loads it. Records are
changed with dynamic updates signed with a key in `parley.dns.updateKeys`, sent to its TCP port.

`DnsServer.main` runs parley-net's launcher with the DNS server (`DnsServerProvider`, `dns` in
`parley.servers`), as the other Parley servers' main methods do: on the platform MBean server (reach it with
the JVM's `com.sun.management.jmxremote.*` settings) the server is `us.bringardner.parley:type=Server,name=dns`,
like every Parley server, and its `Dns` bean is registered while it runs. One DNS server runs in a JVM.

# Dynamic update (RFC 2136)

Allowed for requests signed with a key in `parley.dns.updateKeys`, or unsigned from an address in `parley.dns.updateAllow` (over TCP, or over UDP from this machine); everyone else gets REFUSED. Prerequisites, adds and all three kinds of delete are supported, with the RFC's rules (the apex SOA and NS RRset can't be deleted, never the last NS, no other data next to a CNAME). An update is all or nothing.

The zone file is never rewritten. Changes are appended to a journal next to it, `<zone file>.jnl`, before they are served, and replayed on top of the zone file when it is loaded. Each change raises the SOA serial by one and sends NOTIFY to the secondaries. To edit a zone by hand after updates, edit the zone file (it keeps the updates as long as the serial stays the same) or raise its serial to start over: the journal is then renamed `.jnl.old` and not used. Each update is written between `begin` and `end` lines and synced to disk; an update cut off by a crash is left out when the journal is replayed. Updates can add A, AAAA, NS, CNAME, PTR, MX, TXT, SPF, HINFO, SRV, CAA, HTTPS, SVCB, DS and SSHFP records; other types are REFUSED. An update is also REFUSED, as a whole, when one of its changes can't be written to the journal and read back unchanged, for example a name containing a space or a line break. A signed zone is signed again after each update. Send updates with `nsupdate` or [NsUpdate](#nsupdate).

# DNSSEC

A zone is signed when the key directory (`parley.dns.dnssecKeyDir`, by default the zone directory) has keys for it. The server signs it when it loads it, after every dynamic update or dynamic entry change, and again before the signatures expire; nothing needs to be run by hand after the keys exist.

1. Make a key: `java -cp parley-dns.jar:parley-core.jar:parley-io.jar:parley-net.jar us.bringardner.parley.dns.dnssec.DnssecKeyTool keygen -d zones example.com`. This writes `Kexample.com.+013+<tag>.key` and `.private` (keep that one secret) and prints the DS record. One key (ECDSA P-256, a combined signing key) is all a zone needs; `-ksk` / `-zsk` make separate key and zone signing keys, `-a` picks the algorithm: ECDSAP256SHA256 (default), ECDSAP384SHA384, ED25519 (Java 15 or later), RSASHA256, RSASHA512. Keys made with BIND's `dnssec-keygen` work too.
2. Start (or wait for the next reload): the zone is served signed.
3. Give the DS record to the parent zone (your registrar). `DnssecKeyTool ds -d zones example.com` prints it again. Until the parent has it, validators treat the zone as unsigned; once it does, they reject answers that don't verify.

What the server does:
 +  Adds the DNSKEY set and an NSEC chain, and signs every RRset: the DNSKEY set with the key signing keys (flags 257), the rest with the zone signing keys (256), or everything with one key if there is only one kind. At a delegation only the DS set and the NSEC are signed; glue is not.
 +  Answers queries with the DO bit with the RRSIGs, and proves what doesn't exist with NSEC records (NXDOMAIN, NODATA, wildcards, delegations without a DS). Queries without the DO bit get the same answers as before.
 +  NSEC3 (RFC 5155) instead of NSEC for the zones in `parley.dns.dnssecNsec3` (`*` for all): the chain holds hashes of the names, so it can't be walked to list the zone. The defaults follow RFC 9276 (0 extra iterations, no salt, no opt-out); `parley.dns.dnssecNsec3Iterations` (at most 100) and `parley.dns.dnssecNsec3Salt` change them. Switching a zone between NSEC and NSEC3 re-signs it.
 +  DS records go in the parent zone file at the delegation, e.g. `child IN DS 12345 13 2 <digest>`. A DS query is answered from the parent, even when the server serves the child too.
 +  Signatures are valid for `parley.dns.dnssecValidity` (14 days) from an hour ago. When a quarter is left the zone is signed again with the next serial (written to the journal, so it survives a restart) and the secondaries get a NOTIFY. Zone transfers include the signatures.
 +  Key rollover: every key file of a zone is used. A `.key` file without its `.private` file is published in the DNSKEY set but doesn't sign. BIND's timing fields in the `.private` file (`Publish`, `Activate`, `Inactive`, `Delete`, set with `dnssec-settime`) are followed. Adding, removing or changing a key file re-signs the zone.
 +  If a zone can't be signed (e.g. no key has its private file), the error is logged and the last signed version is served while its signatures are valid, even when the zone file has changed since (served unsigned, every validator would reject the zone while the parent has a DS). An UPDATE that can't be signed is not made (SERVFAIL). Only a zone with no valid signatures left is served unsigned.

Zones signed elsewhere (for example with BIND's `dnssec-signzone`, NSEC or NSEC3, so the private keys never touch the server): put the signed file in the zone directory as `<zone>.txt`. A zone file with RRSIG records is served with its own DNSKEY, RRSIG, NSEC / NSEC3 and NSEC3PARAM records, with the same answers and proofs as a zone signed here.
 +  Every signature is checked when the zone loads; ones that don't verify or have expired are logged (the zone is still served as the signer made it). Keys in the key directory are not used for it.
 +  The server can't sign changes: dynamic UPDATE is REFUSED, and admin-port dynamic entries in such a zone are served without signatures (logged).
 +  Nothing re-signs it here: a warning is logged every 6 hours from 3 days before the first signature expires. Sign it again and replace the file (a changed file is reloaded).
 +  A zone file with DNSKEY, NSEC or NSEC3 records but no RRSIG is refused.

In a signed zone:
 +  Wildcards follow RFC 4592, as validators expect: `*.example.com` also matches `a.b.example.com`, but never a name that exists or has names below it.
 +  An SOA query for a name other than the apex gets NODATA (the made-up SOA the default zone gives other names can't be signed).
 +  DNSKEY, RRSIG, NSEC, NSEC3 and NSEC3PARAM records can't be added with UPDATE (DS can); in a zone file they make it a zone signed elsewhere.
 +  Names outside the zone itself (the `*.*.` patterns a default zone uses for other domains) are served unsigned.

### Validating (resolver)

With `parley.dns.dnssecValidation=true` the resolver validates the answers it fetches for clients (RFC 4033-4035, RFC 5155, RFC 6840): it asks upstream servers for the DNSSEC records (DO), follows the chain of trust down from the trust anchors (by default the root zone's keys, KSK-2017 and KSK-2024) with the DS and DNSKEY records, and checks every signature and every proof that something does not exist.
 +  Secure answers get the AD bit when the client set DO or AD, and carry only the records that were validated: anything else in the answer or authority section (an unsigned record added on the way) is removed. Answers under a delegation proven to be unsigned (or signed only with algorithms we don't support) are passed on without it. Answers that fail validation (bad or missing signatures, expired ones, a missing proof) are BOGUS: the client gets SERVFAIL, and the reason is logged.
 +  A client that sets CD gets the answer without validation (it validates itself). Clients that don't set DO get no RRSIG, NSEC or NSEC3 records.
 +  Algorithms: RSASHA1 and NSEC3RSASHA1 (validation only), RSASHA256, RSASHA512, ECDSA P-256 and P-384, Ed25519 (Java 15+). DS digests SHA-1, SHA-256, SHA-384. NSEC3 with more than 150 iterations, and answers resting on an opt-out NSEC3, are treated as insecure (RFC 9276, RFC 5155 9.2).
 +  Key sets and zone cuts are cached (their TTLs, at most an hour; failures for a minute).
 +  The result is kept with the cached answer, so a cached answer is validated once, not on every query. A BOGUS answer is not kept: the next query fetches it again.
 +  One validation may check at most 150 signatures, and at most 16 of them may fail, and only the first 8 NSEC/NSEC3 records of a response are checked (a proof needs at most 3); an answer that needs more is BOGUS. This stops zones built to make validators do a huge number of signature checks (KeyTrap, CVE-2023-50387); a normal answer needs a handful, and even a 34-label ip6.arpa name looked up from an empty cache stays well within it.
 +  `parley.dns.dnssecTrustAnchors` names a file of anchors, one DS or DNSKEY record per line (BIND's `root.key` or `root.ds` work), e.g. for a private zone; it replaces the built in root anchors. The root anchors are not updated automatically: if the root zone rolls its key again, update parley-dns or give the new key in this file.
 +  Validation needs correct time on the server (signatures have validity periods) and upstream servers that pass on DNSSEC records.
 +  It only matters when parley-dns resolves for clients (`parley.dns.recursionAvailable=true`); an authoritative-only server doesn't need it.
   
 
Dependencies:  
+ [parley-core](https://github.com/parley-project/parley-core)  
+ [parley-io](https://github.com/parley-project/parley-io)  
+ [parley-net](https://github.com/parley-project/parley-net) (TCP and admin servers, upstream health tracking)
 			

# SSH host keys in DNS (SSHFP)

SSHFP records (RFC 4255, RFC 6594) publish the fingerprints of a host's SSH keys, so an SSH client can check a server's key without asking the user. They prove something only when the answer is DNSSEC validated.

+  `us.bringardner.parley.dns.util.SshfpTool [-sha1] host [key.pub ...]` prints the records for a host's public keys (by default `/etc/ssh/ssh_host_*_key.pub`), like `ssh-keygen -r`. Put them in a signed zone; zone files and dynamic UPDATE accept `SSHFP`.
+  `us.bringardner.parley.dns.resolve.SshfpVerifier.verify(host, keyBlob)` checks a host key (SSH wire form, or an OpenSSH public key line) through the resolver with validation on (`parley.dns.dnssecValidation=true`): `MATCH`, `MISMATCH`, `NO_RECORDS`, `INSECURE` (unsigned, or validation off), `BOGUS` or `TEMPFAIL`. Only `MATCH` should let a client accept a key it hasn't seen before. With parley-ssh, `HostKeyVerifiers.withLookup` takes it as the lookup in front of known_hosts (parley-ssh doesn't depend on parley-dns).

# Typed lookups (client API)

`us.bringardner.parley.dns.resolve.Lookup` asks the resolver for one record type and returns the values with a status, for code such as SPF, DKIM and DMARC checks that needs to tell "no such name" from "no record" from "try again later".

```java
LookupResult<String> r = Lookup.txt("_dmarc.example.com");
switch( r.getStatus() ) {
    case OK:       use(r.getValues()); break;   // each TXT record's strings joined
    case NXDOMAIN:                               // the name does not exist
    case NODATA:   noRecord(); break;            // the name exists, no TXT record
    case TEMPFAIL: tryLater(); break;            // timeout, SERVFAIL, REFUSED...
}
```

+ `txt(name)`, `a(name)`, `aaaa(name)`, `addresses(name)` (A then AAAA), `mx(name)` (lowest preference first), `ptr(InetAddress)` / `ptr("192.0.2.1")`, and `records(name, type)` for any other type.
+ CNAMEs are followed; only records of the type asked are returned. A CNAME to a name that does not exist gives NXDOMAIN.
+ `Lookup.txt(name, response)` and `Lookup.fromResponse(...)` apply the same rules to a response you got another way, e.g. from a query sent straight to a recursive server (parley-smtp's `ParleyDnsMxResolver` does this for DKIM keys).
+ Answers come from and go into the resolver cache. The resolver must be initialized (`Resolver.initResolver()`); with no servers configured a lookup that misses the cache is TEMPFAIL.

`us.bringardner.parley.dns.ReverseName` makes the `in-addr.arpa` / `ip6.arpa` name of an address (`ReverseName.of(addr)`, or `of("2001:db8::1")`, which returns null for text that is not an address literal) and turns one back into an address (`toAddress`).

# NsLookup

`us.bringardner.parley.dns.util.NsLookup` works like the Linux (ISC BIND 9) `nslookup`: the same command line, interactive commands, options, output and exit status. Its output was checked line by line against `nslookup` 9.18 (`TestNsLookupOffline` replays the recorded output).

```
java -cp parley-dns.jar:parley-core.jar:parley-io.jar:parley-net.jar us.bringardner.parley.dns.util.NsLookup [-option ...] [host [server]]
java ... NsLookup -type=mx example.com 192.0.2.53
java ... NsLookup -port=5353 -debug www.example.com 127.0.0.1
java ... NsLookup 192.0.2.1              # an address: its PTR record
java ... NsLookup - 127.0.0.1            # interactive, using 127.0.0.1
```

+ **Default server**: the `nameserver` lines of `/etc/resolv.conf` (another file with `-Dparley.dns.resolvConf=path`), tried in order; its `search`/`domain` list and `options ndots: timeout: attempts:` are used too. Without a resolv.conf (Windows) the servers Java finds for the platform are used, and as a last resort a root server.
+ **Lookups**: with no type set, a name gets A and AAAA lookups (following CNAMEs), as `nslookup` does. An IPv4 or IPv6 address is looked up as its `in-addr.arpa` / `ip6.arpa` PTR name. Names with fewer dots than `ndots` try the search list first, then the name itself; a trailing dot means the name as is.
+ **Interactive commands**: `NAME [SERVER]`, `server NAME`, `lserver NAME`, `set OPTION`, `help` or `?`, `exit` (or `quit`).
+ **Options** (`set OPTION`, or `-OPTION` on the command line; like `nslookup`, a unique prefix works, e.g. `set deb`, `-q=mx`): `all`, `type=` (`querytype=`), `class=`, `domain=`, `srchlist=a/b/c`, `port=`, `timeout=` (seconds), `retry=`, `ndots=`, `[no]debug`, `[no]d2`, `[no]recurse`, `[no]search` (`[no]defname`), `[no]vc` (TCP; ANY queries use TCP unless `novc` is set), `[no]fail` (`nofail`: try the next server after SERVFAIL).
+ **Exit status**: 1 if a lookup failed (an error answer such as NXDOMAIN, or no server could be reached), else 0.

Differences from `nslookup`: `help` prints the commands (nslookup says it is not implemented), `quit` exits (nslookup looks up the host "quit"), `srchlist=` is accepted (from the older nslookup), `d2` turns on parley-dns debug logging, and `NAME SERVER` works in interactive mode (as the nslookup manual says; BIND 9 ignores the server there). `ls`, `finger`, `root` and `view` are not implemented, as in BIND 9.

| Property | Default | Meaning |
|---|---|---|
| `parley.dns.resolvConf` | `/etc/resolv.conf` | The resolv.conf NsLookup reads its default servers, search list and options from |

The old options `-s SERVER` and `-p PORT` are gone: use `nslookup host SERVER` and `-port=PORT`. The old `set debug=y`, `set recurse y` and `set udp` forms are replaced by `set debug` / `set nodebug`, `set recurse` / `set norecurse` and `set novc`.

# NsUpdate

`us.bringardner.parley.dns.util.NsUpdate` works like the ISC BIND 9 `nsupdate` (RFC 2136 dynamic update): the same command line, commands, output (`show`, `answer`, `-d`), messages and exit status. It was checked against `nsupdate` 9.18 on the same scripts and server, output and resulting zone (`TestNsUpdate` replays 64 recorded cases).

```
java -cp parley-dns.jar:parley-core.jar:parley-io.jar:parley-net.jar us.bringardner.parley.dns.util.NsUpdate [options] [script]
```

```
server 192.0.2.53
zone example.com
update delete www.example.com A
update add www.example.com 300 A 192.0.2.80
send
```

+ **Command line**: `-y [hmac:]keyname:secret` or `-k keyfile` (a named.conf `key` clause as `tsig-keygen` writes it, or a `K*.+163+*` pair) sign the updates with TSIG; `-l` (localhost, key from `/var/run/named/session.key`), `-p port`, `-v` (TCP), `-t timeout`, `-u udptimeout`, `-r udpretries`, `-C resolv.conf`, `-d`/`-D` (debug), `-i`, `-4`/`-6`, `-V`. Without a script file, commands come from standard input.
+ **Commands**: `server name [port]`, `local address [port]`, `zone name`, `class`, `ttl`, `key [hmac:]name secret`, `check-names on|off`, `[prereq] nxdomain|yxdomain|nxrrset|yxrrset ...`, `[update] add|del[ete] ...`, `show`, `send` (or a blank line), `answer`, `debug`, `version`, `help`, `quit`. Record data is written as in a zone file (all the types parley-dns reads, and `\# length hex` for any type); names are absolute.
+ **Finding the zone**: without `zone` and `server`, the zone and its primary come from an SOA query to the servers in resolv.conf (as `nsupdate`), then the update goes to the primary named in the SOA.
+ **Exit status**: 0; 1 for a syntax or setup error (a script stops at the first one); 2 when an update failed (e.g. `update failed: NXRRSET`).

Differences from `nsupdate`: no GSS-TSIG (`-g`, `-o`), SIG(0) keys or truncated MACs (`hmac-sha256-128`); `-T` lists the types parley-dns knows and `-P` none; the time stamped messages of BIND's own log (e.g. `dns_rdata_fromtext: ... near '10.3.0.999'` before "invalid rdata format") are not printed; `-D` prints fewer internal steps.

# Running in production

Run the server under a supervisor (systemd, launchd, a container runtime) that restarts it when it stops, and let the JVM exit on fatal errors instead of limping on:

```
java -Xmx256m -XX:+ExitOnOutOfMemoryError \
     -Dparley.dns.configFile=/data/services/dns/config/parley-dns.properties \
     -cp parley-dns.jar:parley-core.jar:parley-io.jar:parley-net.jar us.bringardner.parley.dns.server.DnsServer
```

`DnsServer.main` also installs `FatalErrorHandler`: any thread that dies from an uncaught error is logged, and on a JVM error (e.g. `OutOfMemoryError`) the process halts with exit code 1 so the supervisor starts a clean one. Set `-Dparley.dns.exitOnFatalError=false` to only log. Applications that embed the server can call `FatalErrorHandler.install(true)` (`us.bringardner.parley.net.FatalErrorHandler`, from parley-net).

If the server can't start (bad configuration, missing zone directory, a port in use), `DnsServer.main` logs why and exits with -1 (configuration, zones, UDP/TCP sockets) or -2 (admin socket). Applications that embed the server call `start()` and then `awaitStarted(timeoutMs)`, which throws `DnsServer.StartupException` with the cause and stops anything that had started; the server itself never calls `System.exit`.

Malformed requests are answered cheaply and never logged as errors: a request without exactly one question (QDCOUNT 0 or more than 1, RFC 9619; for UPDATE, ZOCOUNT ≠ 1) gets one FORMERR with no question section, and a packet with QR=1 (a response) gets no reply at all. `DnsServer.getQuestionCountErrors()` counts the FORMERRs.

Example systemd unit:

```
[Unit]
Description=parley-dns
After=network-online.target

[Service]
ExecStart=/usr/bin/java -Xmx256m -XX:+ExitOnOutOfMemoryError -Dparley.dns.configFile=/data/services/dns/config/parley-dns.properties -cp /opt/parley-dns/lib/* us.bringardner.parley.dns.server.DnsServer
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

## Configuration properties

Set them in the properties file (`parley.dns.configFile`, see below) or with `-D` on the command line; `-D` wins. Every parley-dns property starts with `parley.dns.`.

A bind address of `localhost` means this host's own name (its network address), not the loopback interface, so the server is reachable from the network; a warning is logged. Use `127.0.0.1` to listen on loopback only.

### Files and zones

| Property | Default | Meaning |
|---|---|---|
| `parley.dns.configFile` | `parley-dns.properties` (current directory) | The properties file to load at startup |
| `parley.dns.dnsDir` | `/data/services/dns/config` | Directory for the dynamic entries file, the TSIG key file and the root hints (`sbelt.prop`) |
| `parley.dns.zoneDir` | `zones` | Directory of the zone files (`<zone>.txt`); a changed file is reloaded |
| `parley.dns.masterZone` | required | The default zone: answers for the common domains (see Major Features) come from it |
| `parley.dns.mailSettings` | none | The mail servers' shared settings (the mail queue's `queue.properties`): its domains are served from the master zone with no zone files, and its DKIM keys' records (see Mail domains) |
| `parley.dns.dynamicFileName` | `dynamic.txt` | Dynamic entries file, relative to `parley.dns.dnsDir` (used without a database) |
| `parley.dns.debug` | true | Debug logging checks; false skips the work of building debug messages |
| `parley.dns.recursionAvailable` | true | Recursion available: resolve names that are not in our zones for clients that ask for it |
| `parley.dns.exitOnFatalError` | true (standalone) | Halt the process on a JVM error (see above) |

### Network

TCP is served by parley-net's `NioServer` (a few reactor threads read and write every connection; requests are answered on a worker pool), with per-client limits and an idle / frame deadline. UDP stays in parley-dns. Upstream server hold-off uses parley-net's `UpstreamHealth`.

| Property | Default | Meaning |
|---|---|---|
| `parley.dns.port` | 53 | DNS port (UDP and TCP) |
| `parley.dns.bindAddress` | loopback | Listen address |
| `parley.dns.udpPort` / `parley.dns.tcpPort` | `parley.dns.port` | Per-protocol port |
| `parley.dns.udpBindAddress` / `parley.dns.tcpBindAddress` | `parley.dns.bindAddress` | Per-protocol listen address |
| `parley.dns.timeout` | 5000 | Socket timeout (ms) for both protocols |
| `parley.dns.udpTimeout` / `parley.dns.tcpTimeout` | `parley.dns.timeout` | Per-protocol socket timeouts (ms); how often the UDP listeners check for shutdown (TCP: no longer used) |
| `parley.dns.udpProcCount` | 10 | UDP listener threads |
| `parley.dns.tcpProcCount` | 1 | TCP reactor threads, which read and write every connection (requests are answered on a pool of up to `parley.dns.tcpMaxConnections` threads) |
| `parley.dns.tcpBacklog` | 10 | TCP listen backlog |
| `parley.dns.tcpMaxConnections` | 64 | TCP connections served at once; more are closed immediately |
| `parley.dns.tcpMaxConnectionsPerClient` | 8 | TCP connections from one client address; more are closed immediately (0: no limit) |
| `parley.dns.tcpIdleTimeout` | 10000 | An idle TCP connection is closed after this many ms; a message that has started must also arrive within it |
| `parley.dns.udpMaxResponse` | 512 | Largest UDP response (bytes) to clients without EDNS; bigger answers are truncated (TC) and clients retry over TCP |
| `parley.dns.ednsUdpSize` | 1232 | Largest UDP response to EDNS clients (512–4096; the client's own size is used if smaller). Responses echo an OPT record; EDNS versions other than 0 get BADVERS |
| `parley.dns.zoneCutReferrals` | true | Names at or below NS records below a zone's apex (a delegation) get a referral (NS + glue, not authoritative) instead of NXDOMAIN / an authoritative answer. Set false if your zones put NS records on ordinary hosts |
| `parley.dns.udpDumpFile` | none | Write every UDP request and answer to this file (debugging) |

### Resolver (recursion)

| Property | Default | Meaning |
|---|---|---|
| `parley.dns.resolvers` | 10 | Resolver threads (for names not in the cache; cached answers to UDP queries are sent by the UDP threads directly) |
| `parley.dns.resolverMaxBacklog` | 200 | Queued recursive queries; when full, clients get SERVFAIL (a CNAME answer is sent without the target's records). Logged at most every 10 s |
| `parley.dns.resolverMaxQueueAge` | 3000 | A queued recursive query that waited longer than this (ms) is dropped: its client has given up (0: never) |
| `parley.dns.resolverVirtualThreads` | true | Resolver threads are virtual threads where the JVM has them (Java 21+) |
| `parley.dns.resolveTimeout` | 4000 | Total time (ms) for one resolution, including referrals and CNAME hops |
| `parley.dns.maxCacheEntries` | 10000 | Resolver cache size (LRU) |
| `parley.dns.cacheSweepSeconds` | 60 | How often expired cache entries are removed |
| `parley.dns.maxCacheAge` | 1800000 | Upper bound (ms) on how long anything is cached |
| `parley.dns.maxNegativeTtl` | 10800 | Upper bound (s) for caching "does not exist" answers |
| `parley.dns.maxDelegations` | 10000 | Learned delegations kept (LRU) |
| `parley.dns.delegationMaxAge` | 3600 | Seconds a learned delegation is used before a fresh referral replaces it |
| `parley.dns.upstreamHoldOffMin` | 5 | Seconds an upstream server address is skipped after 3 failures in a row; doubled for each further failure |
| `parley.dns.upstreamHoldOffMax` | 600 | Longest hold-off (s). When every address of a zone is held off, the one that comes back first is still tried, at most once a second, so recursion recovers within seconds of an outage ending |
| `parley.dns.dnssecValidation` | false | Validate the answers of recursive queries with DNSSEC (see "Validating") |
| `parley.dns.dnssecTrustAnchors` | the root zone's keys (built in) | File of trust anchors (DS or DNSKEY records), relative to `parley.dns.dnsDir` |

### Admin port

The admin port runs on parley-net's `Server` (one thread per session, virtual threads on Java 24+), and `DnsAdminClient` on its `Client`. The protocol is unchanged. Zone reloads, dynamic records and re-signing run on a thread of their own (`DnsMaintenance`), so an error in one of them is logged and the next round goes ahead.

| Property | Default | Meaning |
|---|---|---|
| `parley.dns.adminPort` | 9999 | Admin port; `DnsAdminClient` connects to it too |
| `parley.dns.adminHost` | the DNS server NsLookup finds, else localhost | Host `DnsAdminClient` connects to (a command line argument wins) |
| `parley.dns.adminBindAddress` | loopback | Admin port listen address (`0.0.0.0` for all interfaces) |
| `parley.dns.adminSecret` | none | Shared secret for the admin port (challenge-response). Without it only local clients are accepted. `DnsAdminClient` reads the same property |
| `parley.dns.adminTls` | false | TLS on the admin port, using the standard `javax.net.ssl.keyStore` / `keyStorePassword` properties (client: `javax.net.ssl.trustStore`). `DnsAdminClient` reads the same property. Recommended when `parley.dns.adminBindAddress` is not loopback: the challenge-response protects the secret, not the session |
| `parley.dns.adminMaxConnections` | 8 | Admin sessions at once |
| `parley.dns.adminIdleTimeout` | 600000 | Idle admin sessions are closed after this many ms |
| `parley.dns.adminMaxLine` | 8192 | Longest admin command line in bytes; a longer line ends the session |
| `parley.dns.adminAuthTimeout` | 30000 | With `parley.dns.adminSecret` set, a session that hasn't authenticated after this many ms is closed |

### Database

| Property | Default | Meaning |
|---|---|---|
| `parley.dns.useDatabase` | only if `parley.dns.jdbcUrl` is set | Use the database for common domains and dynamic records |
| `parley.dns.jdbcUrl` | none | JDBC URL of the database |
| `parley.dns.jdbcDriver` | none | JDBC driver class to load (not needed for JDBC 4 drivers on the class path) |
| `parley.dns.jdbcUser` / `parley.dns.jdbcPassword` | none | Database login |

### Zone transfer, TSIG, dynamic update

| Property | Default | Meaning |
|---|---|---|
| `parley.dns.axfrAllow` | none | Addresses / networks allowed to transfer zones over TCP (AXFR, RFC 5936), e.g. `192.0.2.2, 10.0.0.0/8, 2001:db8::/32`. Everyone else gets REFUSED, unless the request is signed with a key in `parley.dns.axfrKeys` |
| `parley.dns.axfrKeys` | none | TSIG key names whose signed requests may transfer zones, from any address |
| `parley.dns.notify` | none | Secondaries to send NOTIFY (RFC 1996) to when a zone is loaded or its SOA serial changes, e.g. `192.0.2.2, [2001:db8::2]:53`. Bump the serial when you edit a zone. Dynamic entries don't change the serial, so secondaries only see them at their next transfer |
| `parley.dns.notifyKey` | none | TSIG key to sign NOTIFY messages with; the secondary's answer must then be signed too |
| `parley.dns.notifyRetries` | 5 | Attempts per NOTIFY |
| `parley.dns.notifyTimeout` | 2000 | First wait (ms) for a NOTIFY answer, doubled after each attempt |
| `parley.dns.tsigKeys` | none | TSIG keys (RFC 8945) as `name:algorithm:base64secret`, e.g. `xfr.example:hmac-sha256:...`. Algorithms: hmac-sha256 (recommended), hmac-sha512, hmac-sha384, hmac-sha224, hmac-sha1, hmac-md5. Generate a secret with `openssl rand -base64 32`. A request signed with a known key gets a signed response; a bad signature, an unknown key or a clock too far off (see `parley.dns.tsigFudge`) gets NOTAUTH and is not answered. A signed UPDATE or zone transfer request is acted on once. The same UPDATE sent again (a retransmission, or a replay) gets the first answer again without being applied a second time; the same transfer request gets NOTAUTH with BADTIME. Plain queries may be repeated |
| `parley.dns.tsigKeyFile` | none | A file of TSIG keys, one `name algorithm secret` per line (`#` comments); relative to `parley.dns.dnsDir`. Keeps the secrets out of the properties file |
| `parley.dns.tsigFudge` | 300 | Largest clock difference (seconds, 1-65535) accepted in a signed request; also the fudge used when signing NOTIFY. The window is the smaller of this and the fudge in the request, so a client can't widen it |
| `parley.dns.updateKeys` | none | TSIG key names whose signed dynamic UPDATE requests (RFC 2136, e.g. `nsupdate -k`) may change zones |
| `parley.dns.updateAllow` | none | Addresses / networks allowed to send unsigned UPDATE requests. Over UDP this applies to this machine (loopback) only, because a UDP source address can be forged: other addresses must send over TCP (`nsupdate -v`) or sign with a key. Prefer `parley.dns.updateKeys` |

### DNSSEC

| Property | Default | Meaning |
|---|---|---|
| `parley.dns.dnssecKeyDir` | `parley.dns.zoneDir` | Directory of the DNSSEC key files (`K<zone>.+<alg>+<tag>.key` and `.private`). A zone with keys there is signed |
| `parley.dns.dnssecValidity` | 14d | How long DNSSEC signatures are valid (at least 1h); zones are signed again when a quarter of it is left |
| `parley.dns.dnssecNsec3` | none | Zones to sign with NSEC3 instead of NSEC, e.g. `example.com, example.org`, or `*` for all |
| `parley.dns.dnssecNsec3Iterations` | 0 | NSEC3 extra hash iterations (0-100; RFC 9276 recommends 0) |
| `parley.dns.dnssecNsec3Salt` | - | NSEC3 salt in hex, `-` for none (RFC 9276 recommends none) |

### Logging (parley-core)

Logging comes from the parley-core library, whose property names are its own: `logLevel` (default ERROR; e.g. DEBUG, INFO), `<logger name>.logLevel` for one logger, `logFile` (default: standard output) and `parley.core.logger` (the logger class).

### Renamed properties

In 2.0.0 every `JDns.*` property was renamed to `parley.dns.*`, and the old names are no longer read.
Most keep the rest of their name (`JDns.adminPort` is `parley.dns.adminPort`); these changed more:

| 1.x name | 2.0.0 name |
|---|---|
| `JDns.dnsPort` | `parley.dns.port` |
| `JDns.master.zone` | `parley.dns.masterZone` |
| `JDns.zone.dir` | `parley.dns.zoneDir` |
| `JDns.udp.bindAddress` | `parley.dns.udpBindAddress` |
| `JDns.dump.file` | `parley.dns.udpDumpFile` |
| `JDns.ra` | `parley.dns.recursionAvailable` |
| `JDns.jdbcURL`, `JDns.jdbcClass` | `parley.dns.jdbcUrl`, `parley.dns.jdbcDriver` |
| `JDns.useDataBase` | `parley.dns.useDatabase` |
| `JDns.properties` | `parley.dns.configFile`; the default file is now `parley-dns.properties` (was `JDns.properties`) |
| `echoCommand` (NsLookup) | `parley.dns.nslookup.echoCommand` |

The older names 1.0.0 still read with a warning (`UDPProcCount`, `TCPProcCount`, `Resolver.maxBacklog`, and
`name` and `port` for DnsAdminClient) are no longer read either: use `parley.dns.udpProcCount`,
`parley.dns.tcpProcCount`, `parley.dns.resolverMaxBacklog`, `parley.dns.adminHost` and `parley.dns.adminPort`.
