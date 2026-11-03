package us.bringardner.parley.dns.server;

/**
 * The DNS server as JMX sees it ({@code us.bringardner.parley:type=Dns,name=DnsServer}), for
 * management tools. It is an MXBean, so every attribute is a JMX open type and a generic client
 * (JConsole) can read it.
 * <p>
 * Nothing here changes a zone: the server reads zone files and doesn't write them. A zone's records
 * are changed with a dynamic update (RFC 2136), signed with a key in {@code parley.dns.updateKeys},
 * sent to {@link #getTcpPort()}; it is journaled and the secondaries are told, as for any other
 * update. The shared zone's file, and a new zone file, are written by whoever manages them
 * ({@link SharedZoneText} reads, checks and writes their text); the server reads a changed file
 * again ({@link #reload()} at once).
 *
 * @since 2.0.0
 */
public interface DnsServerMXBean {

	/** RUNNING or STOPPED */
	String getState();

	/** When it started (ms since the epoch), or 0 */
	long getStarted();

	/** The TCP port it answers on (dynamic updates go there) */
	int getTcpPort();

	/** Whether it resolves names that are not in its zones for clients that ask */
	boolean isRecursionAvailable();

	/** The names of the TSIG keys allowed to send dynamic updates (never the secrets) */
	String[] getUpdateKeyNames();

	/** The folder of the zone files */
	String getZoneDirectory();

	/** Every zone served, by name */
	DnsZoneInfo[] getZones();

	/**
	 * The records of a zone, with the inherited ones marked (see {@code $INHERIT} in the README).
	 * @throws IllegalArgumentException if the zone isn't served
	 */
	DnsRecordInfo[] getRecords(String zone);

	/** Zone files that failed to load, or zones that can't inherit: "file or zone: why" */
	String[] getErrors();

	/**
	 * Read the zone files again (changed files only; a zone that fails keeps its previous version)
	 * and build the inheriting zones again.
	 */
	void reload() throws Exception;

	/** The shared zone's file ({@code parley.dns.sharedZone}), or null when it isn't set */
	String getSharedZoneFile();

	/**
	 * The record types zone files can have, in a form's order: their data's example and whether
	 * they can be changed (dynamic updates, a managed shared zone). Management tools build
	 * their record forms from this, so a type the server learns needs no change there.
	 */
	DnsRecordType[] getRecordTypes();

	/**
	 * The shared zone's records as its file has them, the SOA first: owners relative to the domain
	 * ({@code @}, {@code www}, {@code *}), relative names in the data left relative ({@code 10 mail}).
	 * @throws IllegalStateException if {@code parley.dns.sharedZone} isn't set, or its file is
	 *  missing or not a valid shared zone
	 */
	DnsRecordInfo[] getSharedRecords() throws Exception;
}
