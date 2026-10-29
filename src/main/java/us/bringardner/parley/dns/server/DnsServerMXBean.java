package us.bringardner.parley.dns.server;

/**
 * The DNS server as JMX sees it ({@code us.bringardner.parley:type=Dns,name=DnsServer}), for
 * management tools such as parley-mail-admin. It is an MXBean, so every attribute is a JMX open
 * type and a generic client (JConsole) can read it.
 * <p>
 * Records are not changed here: send a dynamic update (RFC 2136), signed with a key in
 * {@code parley.dns.updateKeys}, to {@link #getTcpPort()}. The update is journaled and the
 * secondaries are told, as for any other update.
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

	/**
	 * Make the zone file of a domain that inherits the shared zone (a {@code $INHERIT} line and an
	 * SOA like the shared zone's, serial 1) and load it. The domain then serves the shared zone's
	 * records until it adds or overrides some. A listed domain gets its file this way when one of
	 * its records changes.
	 * @param zone the domain, e.g. example.com
	 * @throws IllegalArgumentException if the name isn't a domain name, the zone has a file
	 *  already, or the shared zone isn't set or can't be read
	 */
	void createInheritingZone(String zone) throws Exception;

	/** The shared zone's file ({@code parley.dns.sharedZone}), or null when it isn't set */
	String getSharedZoneFile();

	/**
	 * The record types zone files can have, in a form's order: their data's example and whether
	 * they can be changed (dynamic updates, the shared zone's record calls). Management tools build
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

	/**
	 * Add records to the shared zone: one per value, of the type at the name; values it has
	 * already are left. The TTL becomes the TTL of every record of that name and type (RFC 2181 5.2).
	 * Each change to the shared zone writes its file whole (its comments are not kept), keeps the
	 * one it replaces as {@code <file>.previous}, raises its serial and is served at once.
	 * @param name relative to the domain: {@code @} (or empty), {@code www}, {@code *}
	 * @throws IllegalArgumentException if a value isn't valid data of the type, or the type can't be changed
	 */
	void addSharedRecords(String name, String type, long ttl, String[] values) throws Exception;

	/**
	 * Replace one record of the shared zone (found by name, type and data, as
	 * {@link #getSharedRecords()} gives them) with another: any name, type, TTL and data. The TTL
	 * becomes the TTL of every record of the new name and type. The SOA stays an SOA at {@code @};
	 * its serial is raised past the file's if the new one isn't higher.
	 * @throws IllegalStateException if the record isn't there (changed meanwhile)
	 */
	void changeSharedRecord(String name, String type, String data, String newName, String newType, long ttl, String newData) throws Exception;

	/**
	 * Delete one record of the shared zone (found by name, type and data). The SOA can't be deleted.
	 * @throws IllegalStateException if the record isn't there (changed meanwhile)
	 */
	void deleteSharedRecord(String name, String type, String data) throws Exception;
}
