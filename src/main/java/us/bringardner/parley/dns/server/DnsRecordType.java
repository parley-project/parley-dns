package us.bringardner.parley.dns.server;

import java.beans.ConstructorProperties;

/** A record type the DNS server reads, as {@link DnsServerMXBean#getRecordTypes()} reports it. */
public class DnsRecordType {

	private final String name;
	private final String example;
	private final boolean editable;

	@ConstructorProperties({ "name", "example", "editable" })
	public DnsRecordType(String name, String example, boolean editable) {
		this.name = name;
		this.example = example;
		this.editable = editable;
	}

	/** The type's mnemonic: A, MX, TXT... */
	public String getName() {
		return name;
	}

	/** Its data as written in a zone file, for a form's hint (e.g. {@code 10 mail.example.com.}) */
	public String getExample() {
		return example;
	}

	/**
	 * Whether records of the type can be added and changed (dynamic updates, the shared zone);
	 * false for the DNSSEC records, which signing makes or a zone signed elsewhere brings
	 */
	public boolean isEditable() {
		return editable;
	}
}
