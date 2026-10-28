package us.bringardner.parley.dns.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
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
 * <li>each DKIM key's public key ({@code dkim.keys=domain:selector:keyfile}) at
 *     {@code selector._domainkey.domain}, from the record text parley-mail-admin keeps beside the key
 *     ({@code keyfile.txt}), or made from the key itself, unless the zone has records at that name;</li>
 * <li>in the master zone, the DMARC report authorization of every listed domain of another
 *     organization ({@code domain._report._dmarc.master}, RFC 7489 7.1), so the reports a domain's
 *     inherited DMARC record asks for reach the master zone's address.</li>
 * </ul>
 * The settings are read again when the file, or a key file it names, changes.
 */
final class MailDomains {

	static final String DOMAINS = "domains";
	static final String DKIM_KEYS = "dkim.keys";
	static final String REPORT = "._report._dmarc.";

	private static final Pattern DOMAIN = Pattern.compile("(?i)[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+");
	private static final Pattern SELECTOR = Pattern.compile("(?i)[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?");

	/** What was read: the domains, and the DKIM records by owner name (lower case, no trailing dot). */
	static final class Snapshot {
		static final Snapshot EMPTY = new Snapshot(Collections.<String>emptySet(), Collections.<String, String>emptyMap(),
				Collections.<String>emptyList());
		final Set<String> domains;
		final Map<String, String> dkim;
		final List<String> errors;

		Snapshot(Set<String> domains, Map<String, String> dkim, List<String> errors) {
			this.domains = Collections.unmodifiableSet(domains);
			this.dkim = Collections.unmodifiableMap(dkim);
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
	 * @return true if what is served changed (the domains or a DKIM record)
	 */
	synchronized boolean reload() {
		if( !changed() ) {
			return false;
		}
		Map<File, String> seen = new LinkedHashMap<File, String>();
		seen.put(file, stamp(file));
		Set<String> domains = new TreeSet<String>();
		Map<String, String> dkim = new HashMap<String, String>();
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
		for(String k : split(p.getProperty(DKIM_KEYS))) {
			String[] parts = k.split(":", 3);
			if( parts.length != 3 ) {
				errors.add(DKIM_KEYS+": not domain:selector:keyfile: "+k);
				continue;
			}
			String domain = strip(parts[0].trim()).toLowerCase(Locale.ROOT);
			String selector = parts[1].trim().toLowerCase(Locale.ROOT);
			File key = new File(parts[2].trim());
			File txt = new File(key.getPath()+".txt");
			if( !DOMAIN.matcher(domain).matches() || !SELECTOR.matcher(selector).matches() ) {
				errors.add(DKIM_KEYS+": not a domain and selector: "+k);
				continue;
			}
			seen.put(key, stamp(key));
			seen.put(txt, stamp(txt));
			try {
				dkim.put(selector+"._domainkey."+domain, dkimRecord(key, txt));
			} catch(IOException | RuntimeException e) {
				errors.add("DKIM key of "+domain+" ("+selector+"): "+e.getMessage());
			}
		}
		Snapshot before = snapshot;
		snapshot = new Snapshot(domains, dkim, errors);
		stamps = seen;
		return !before.domains.equals(domains) || !before.dkim.equals(dkim);
	}

	/**
	 * A key's DKIM record (RFC 6376 3.6.1): the text parley-mail-admin keeps beside the key, or the
	 * public key of the key itself (PKCS#8 RSA).
	 */
	static String dkimRecord(File key, File txt) throws IOException {
		if( txt.exists() ) {
			String t = new String(Files.readAllBytes(txt.toPath()), StandardCharsets.UTF_8).trim();
			//  a zone file line written as one or more quoted strings: their text, joined
			if( t.startsWith("\"") ) {
				StringBuilder b = new StringBuilder();
				java.util.regex.Matcher m = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"").matcher(t);
				while( m.find() ) {
					b.append(m.group(1).replace("\\\"", "\"").replace("\\\\", "\\"));
				}
				t = b.toString();
			}
			if( !t.startsWith("v=DKIM1") ) {
				throw new IOException(txt+" doesn't hold a DKIM record");
			}
			return t;
		}
		String pem = new String(Files.readAllBytes(key.toPath()), StandardCharsets.US_ASCII);
		if( !pem.contains("-----BEGIN PRIVATE KEY-----") ) {
			throw new IOException(key+": not a PKCS#8 private key (-----BEGIN PRIVATE KEY-----), and no "+txt.getName());
		}
		String b64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPrivateCrtKey priv = (RSAPrivateCrtKey) kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(b64)));
			BigInteger e = priv.getPublicExponent();
			PublicKey pub = kf.generatePublic(new RSAPublicKeySpec(priv.getModulus(), e));
			return "v=DKIM1; k=rsa; p="+Base64.getEncoder().encodeToString(pub.getEncoded());
		} catch(java.security.GeneralSecurityException | ClassCastException | IllegalArgumentException ex) {
			throw new IOException(key+": not an RSA private key ("+ex.getMessage()+")");
		}
	}

	/**
	 * The text of the TXT record served at a name, or null: a DKIM key's record, or (when the master
	 * zone is asked) the DMARC report authorization of a listed domain.
	 */
	String txt(String name, String master) {
		Snapshot s = snapshot;
		String n = strip(name).toLowerCase(Locale.ROOT);
		String d = s.dkim.get(n);
		if( d != null ) {
			return d;
		}
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
		for(String k : s.dkim.keySet()) {
			if( k.endsWith(n) ) {
				return true;
			}
		}
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
