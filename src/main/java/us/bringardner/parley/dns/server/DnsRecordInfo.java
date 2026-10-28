package us.bringardner.parley.dns.server;

import java.beans.ConstructorProperties;

/** A record of a zone, as {@link DnsServerMXBean} reports it. */
public class DnsRecordInfo {

	private final String name;
	private final String type;
	private final long ttl;
	private final String data;
	private final boolean inherited;

	@ConstructorProperties({ "name", "type", "ttl", "data", "inherited" })
	public DnsRecordInfo(String name, String type, long ttl, String data, boolean inherited) {
		this.name = name;
		this.type = type;
		this.ttl = ttl;
		this.data = data;
		this.inherited = inherited;
	}

	/** The owner name, without the trailing dot */
	public String getName() {
		return name;
	}

	/** The type's mnemonic: A, MX, TXT... */
	public String getType() {
		return type;
	}

	/** Seconds */
	public long getTtl() {
		return ttl;
	}

	/** The data as written in a zone file (e.g. {@code 10 mx1.example.com.}) */
	public String getData() {
		return data;
	}

	/** Copied from the zone it inherits from, not one of the zone's own records */
	public boolean isInherited() {
		return inherited;
	}
}
