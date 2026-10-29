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
	 * The text of the shared zone's file as it is now.
	 * @throws IllegalStateException if {@code parley.dns.sharedZone} isn't set or its file doesn't exist
	 */
	String getSharedZoneText() throws Exception;

	/**
	 * Replace the shared zone's file with this text and serve it at once: every listed domain and
	 * every zone with {@code $INHERIT} serves the new records. The text is checked as the file is
	 * when it is read, the file is replaced whole, and the one it replaces is kept as
	 * {@code <file>.previous}.
	 * @param text the new text (line ends written as \n)
	 * @param expected the text it replaces, as {@link #getSharedZoneText()} returned it, so a change
	 *  made since isn't lost; null to replace whatever is there
	 * @throws IllegalArgumentException if the text isn't a valid shared zone, or its SOA serial isn't
	 *  higher than the file's (secondaries would not see the change)
	 * @throws IllegalStateException if the shared zone isn't set, or its file changed since
	 *  {@code expected} was read
	 */
	void setSharedZoneText(String text, String expected) throws Exception;
}
