package us.bringardner.parley.dns.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * The mail domains, read from the mail servers' shared settings ({@code parley.dns.mailSettings}:
 * the mail queue's {@code queue.properties}, which parley-mail-admin edits). parley-dns serves:
 * <ul>
 * <li>every listed domain ({@code domains=}) that has no zone of its own as a zone inheriting from
 *     the master zone, built in memory with no zone file (see DnsServer.loadZones); its zone file is
 *     written only when one of its records is changed (an UPDATE, e.g. from the admin's DNS page);</li>
 * <li>in the master zone, the DMARC report authorization of every listed domain of another
 *     organization ({@code domain._report._dmarc.master}, RFC 7489 7.1), so the reports a domain's
 *     inherited DMARC record asks for reach the master zone's address.</li>
 * </ul>
 * The settings are read again when the file changes. DKIM keys aren't served from them: a mail
 * domain signs with the shared key (parley-smtp's {@code dkim.shared}), whose record it inherits from
 * the master zone like any other; a domain with a key of its own has its record in its own zone.
 */
final class MailDomains {

	static final String DOMAINS = "domains";
	static final String REPORT = "._report._dmarc.";

	private static final Pattern DOMAIN = Pattern.compile("(?i)[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+");

	/** What was read: the domains (lower case, no trailing dot). */
	static final class Snapshot {
		static final Snapshot EMPTY = new Snapshot(Collections.<String>emptySet(), Collections.<String>emptyList());
		final Set<String> domains;
		final List<String> errors;

		Snapshot(Set<String> domains, List<String> errors) {
			this.domains = Collections.unmodifiableSet(domains);
			this.errors = Collections.unmodifiableList(errors);
		}
	}

	private final File file;
	private volatile Snapshot snapshot = Snapshot.EMPTY;
	//  The files read last time and their stamps, to see a change
	private volatile Map<File, String> stamps = Collections.emptyMap();

	MailDomains(File file) {
		this.file = file;
	}

	File getFile() {
		return file;
	}

	Snapshot get() {
		return snapshot;
	}

	/** Whether the settings file, or a key file it names, changed since the last read. */
	boolean changed() {
		Map<File, String> s = stamps;
		if( s.isEmpty() ) {
			return true;
		}
		for(Map.Entry<File, String> e : s.entrySet()) {
			if( !stamp(e.getKey()).equals(e.getValue()) ) {
				return true;
			}
		}
		return false;
	}

	private static String stamp(File f) {
		return f.exists() ? f.lastModified()+"/"+f.length() : "-";
	}

	/**
	 * Read the settings again if they changed.
	 * @return true if what is served changed (the domains)
	 */
	synchronized boolean reload() {
		if( !changed() ) {
			return false;
		}
		Map<File, String> seen = new LinkedHashMap<File, String>();
		seen.put(file, stamp(file));
		Set<String> domains = new TreeSet<String>();
		List<String> errors = new ArrayList<String>();
		Properties p = new Properties();
		if( !file.exists() ) {
			errors.add(file+": not found");
		} else {
			try(InputStream in = new FileInputStream(file)) {
				p.load(in);
			} catch(IOException e) {
				errors.add(file+": "+e.getMessage());
			}
		}
		for(String d : split(p.getProperty(DOMAINS))) {
			String n = strip(d).toLowerCase(Locale.ROOT);
			if( DOMAIN.matcher(n).matches() ) {
				domains.add(n);
			} else {
				errors.add(DOMAINS+": not a domain name: "+d);
			}
		}
		Snapshot before = snapshot;
		snapshot = new Snapshot(domains, errors);
		stamps = seen;
		return !before.domains.equals(domains);
	}

	/**
	 * The text of the TXT record served at a name, or null: when the master zone is asked, the DMARC
	 * report authorization of a listed domain.
	 */
	String txt(String name, String master) {
		Snapshot s = snapshot;
		String n = strip(name).toLowerCase(Locale.ROOT);
		if( master != null ) {
			String m = strip(master).toLowerCase(Locale.ROOT);
			String tail = REPORT+m;
			if( n.endsWith(tail) ) {
				String domain = n.substring(0, n.length()-tail.length());
				if( s.domains.contains(domain) && !sameOrganization(domain, m) ) {
					return "v=DMARC1";
				}
			}
		}
		return null;
	}

	/** Whether a name has served names below it (an empty non-terminal: NODATA, not NXDOMAIN). */
	boolean hasNamesBelow(String name, String master) {
		Snapshot s = snapshot;
		String n = "."+strip(name).toLowerCase(Locale.ROOT);
		if( master != null ) {
			String m = strip(master).toLowerCase(Locale.ROOT);
			for(String d : s.domains) {
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

	private static List<String> split(String value) {
		List<String> ret = new ArrayList<String>();
		if( value != null ) {
			for(String s : value.split("[,\\s]+")) {
				if( !s.isEmpty() ) {
					ret.add(s);
				}
			}
		}
		return ret;
	}

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}
}
