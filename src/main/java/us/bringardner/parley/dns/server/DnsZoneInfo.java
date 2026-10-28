package us.bringardner.parley.dns.server;

import java.beans.ConstructorProperties;

/** A zone the DNS server serves, as {@link DnsServerMXBean} reports it. */
public class DnsZoneInfo {

	private final String name;
	private final String inheritFrom;
	private final long serial;
	private final long ownSerial;
	private final int records;
	private final int ownRecords;
	private final boolean signed;
	private final String file;

	@ConstructorProperties({ "name", "inheritFrom", "serial", "ownSerial", "records", "ownRecords", "signed", "file" })
	public DnsZoneInfo(String name, String inheritFrom, long serial, long ownSerial, int records, int ownRecords,
			boolean signed, String file) {
		this.name = name;
		this.inheritFrom = inheritFrom;
		this.serial = serial;
		this.ownSerial = ownSerial;
		this.records = records;
		this.ownRecords = ownRecords;
		this.signed = signed;
		this.file = file;
	}

	/** The zone's name, e.g. example.com */
	public String getName() {
		return name;
	}

	/** The zone it inherits from ($INHERIT), or null; null too when it can't (see the server's errors) */
	public String getInheritFrom() {
		return inheritFrom;
	}

	/** The SOA serial served (for an inheriting zone, its own plus the primary's) */
	public long getSerial() {
		return serial;
	}

	/** The serial of the zone's own records (its zone file and updates) */
	public long getOwnSerial() {
		return ownSerial;
	}

	/** Records served, the SOA not counted */
	public int getRecords() {
		return records;
	}

	/** The zone's own records, the SOA not counted */
	public int getOwnRecords() {
		return ownRecords;
	}

	/** Served with DNSSEC signatures */
	public boolean isSigned() {
		return signed;
	}

	/** The zone file, or null */
	public String getFile() {
		return file;
	}
}
