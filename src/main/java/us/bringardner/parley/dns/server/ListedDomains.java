package us.bringardner.parley.dns.server;

import java.util.Collections;
import java.util.Locale;
import java.util.Set;

import us.bringardner.parley.net.server.DomainListUnavailableException;
import us.bringardner.parley.net.server.IDomainList;

/**
 * The listed domains ({@code parley.dns.domainList}): the domains served from the shared zone,
 * from parley-net's {@link IDomainList} (by default the mail queue's {@code queue.properties}
 * {@code domains=}, so mail and DNS share one list). Each listed domain with no zone file is
 * served from the shared zone in memory; one with a zone file is served from it.
 * <p>
 * The master zone also serves, for each listed domain outside it, the DMARC report
 * authorization (RFC 7489 7.1) at {@code domain._report._dmarc.master}, so reports a listed
 * domain's DMARC record asks for reach the master zone's address.
 */
final class ListedDomains {

	static final String REPORT = "._report._dmarc.";

	private final IDomainList list;
	//  the class name and file the list was made with, to see the settings change
	private final String settings;
	private volatile Set<String> domains = Collections.emptySet();

	ListedDomains(IDomainList list, String settings) throws DomainListUnavailableException {
		this.list = list;
		this.settings = settings;
		domains = list.getDomains();
	}

	IDomainList getList() {
		return list;
	}

	String getSettings() {
		return settings;
	}

	/** The domains read last (lower case, no trailing dot). */
	Set<String> domains() {
		return domains;
	}

	/**
	 * Read the list again if it changed.
	 * @return true if the domains changed
	 */
	boolean reloadIfChanged() throws DomainListUnavailableException {
		boolean ret = list.reloadIfChanged();
		domains = list.getDomains();
		return ret;
	}

	/**
	 * The text of the TXT record served at a name, or null: when the master zone is asked, the DMARC
	 * report authorization of a listed domain.
	 */
	String txt(String name, String master) {
		String n = strip(name).toLowerCase(Locale.ROOT);
		if( master != null ) {
			String m = strip(master).toLowerCase(Locale.ROOT);
			String tail = REPORT+m;
			if( n.endsWith(tail) ) {
				String domain = n.substring(0, n.length()-tail.length());
				if( domains.contains(domain) && !sameOrganization(domain, m) ) {
					return "v=DMARC1";
				}
			}
		}
		return null;
	}

	/** Whether a name has served names below it (an empty non-terminal: NODATA, not NXDOMAIN). */
	boolean hasNamesBelow(String name, String master) {
		String n = "."+strip(name).toLowerCase(Locale.ROOT);
		if( master != null ) {
			String m = strip(master).toLowerCase(Locale.ROOT);
			for(String d : domains) {
				if( !sameOrganization(d, m) && (d+REPORT+m).endsWith(n) ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Whether a domain is the master zone or below it. Its reports need no authorization then (the
	 * same organizational domain, RFC 7489 7.1), so none is served for it.
	 */
	static boolean sameOrganization(String domain, String master) {
		return domain.equals(master) || domain.endsWith("."+master);
	}

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}
}
