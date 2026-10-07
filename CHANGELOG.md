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
