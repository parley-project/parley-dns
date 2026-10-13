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

### Changed (behaviour)

- Unsigned dynamic updates allowed by address (`JDns.updateAllow`) are accepted over UDP only from
  this machine (loopback). From other addresses, send them over TCP (`nsupdate -v`) or sign them
  with a key in `JDns.updateKeys`: a UDP source address can be forged.
- A signed UPDATE or zone transfer request is accepted once; the same request again gets NOTAUTH
  (BADTIME).
- An UPDATE is REFUSED when one of its changes can't be written to the journal and read back
  unchanged (e.g. a name containing a space).
- A DNSSEC-validated (SECURE) answer carries only the records that were validated.

### Removed

- `us.bringardner.parley.dns.dynamic.DynamicDns`. Nothing in the library used it, and when its
  `JDns.jdbc*` properties were missing it fell back to a built-in database host and login.
  Dynamic records are kept by `DnsServer` (`dynamic.txt` or the `JDns.jdbc*` database).
