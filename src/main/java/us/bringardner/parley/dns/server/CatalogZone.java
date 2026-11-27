package us.bringardner.parley.dns.server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.RR;

/**
 * A catalog zone (RFC 9432): an ordinary zone whose records list the member zones a primary serves, so a
 * secondary that reads it needs no list of zones of its own.
 * <pre>
 * &#64;                      SOA   invalid. invalid. ( serial ... )
 * &#64;                      NS    invalid.
 * version                TXT   "2"
 * &lt;unique&gt;.zones          PTR   member.example.
 * </pre>
 * The label for a member is a hash of the member's name, so it is the same on every run (a label that
 * changes is a removal and a new member to a secondary, which starts the zone over).
 */
final class CatalogZone {

	/** The schema version this implements (RFC 9432 section 4.1) */
	static final String VERSION = "2";
	/** The label the members are under */
	static final String ZONES = "zones";

	private CatalogZone() {
	}

	/** The member's label: the first 20 hexadecimal digits of the SHA-256 of its lower case name. */
	static String label(String zone) {
		try {
			byte [] h = MessageDigest.getInstance("SHA-256").digest(strip(zone).toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
			StringBuilder b = new StringBuilder();
			for(int i=0; i < 10; i++) {
				b.append(String.format("%02x", h[i] & 0xff));
			}
			return b.toString();
		} catch(NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	/**
	 * The zone file text of the catalog.
	 *
	 * @param members the zones the catalog lists
	 * @param serial the SOA serial (an unsigned 32 bit number in an int)
	 */
	static String text(Collection<String> members, int serial) {
		StringBuilder b = new StringBuilder();
		b.append("; A catalog zone (RFC 9432): the zones this server is the primary for. Generated; changes are lost.\n");
		b.append("$TTL 3600\n");
		b.append("@\tIN\tSOA\tinvalid. invalid. ( ").append(Integer.toUnsignedString(serial)).append(" 600 60 604800 60 )\n");
		b.append("@\tIN\tNS\tinvalid.\n");
		b.append("version\tIN\tTXT\t\"").append(VERSION).append("\"\n");
		for(String m : new TreeSet<String>(members)) {
			b.append(label(m)).append('.').append(ZONES).append("\tIN\tPTR\t").append(strip(m)).append(".\n");
		}
		return b.toString();
	}

	/**
	 * The member zones a catalog lists, in lower case without the final dot.
	 *
	 * @param catalog the catalog zone's name
	 * @param records the zone's records (any order; the SOA and NS are not looked at)
	 * @throws IOException if the catalog is broken (RFC 9432 section 4): no version property, a version this
	 *   does not implement, a member with other than one PTR, or two members for one zone. A broken
	 *   catalog is not used at all.
	 */
	static Set<String> members(String catalog, List<RR> records) throws IOException {
		String cat = strip(catalog).toLowerCase(Locale.ROOT);
		String versionName = "version."+cat;
		String zonesSuffix = "."+ZONES+"."+cat;
		List<String> versions = new ArrayList<String>();
		Set<String> labels = new LinkedHashSet<String>();
		java.util.Map<String, List<String>> ptrs = new java.util.HashMap<String, List<String>>();
		for(RR rr : records) {
			String name = strip(rr.getName()).toLowerCase(Locale.ROOT);
			if( rr.getType() == DNS.TXT && name.equals(versionName) ) {
				versions.add(rr.toString());
				if( !(rr instanceof us.bringardner.parley.dns.Txt) || !VERSION.equals(((us.bringardner.parley.dns.Txt)rr).getText()) ) {
					throw new IOException("The catalog "+cat+" has a version this does not implement (it needs \""+VERSION+"\")");
				}
			} else if( rr.getType() == DNS.PTR && name.endsWith(zonesSuffix) ) {
				String label = name.substring(0, name.length()-zonesSuffix.length());
				if( label.isEmpty() || label.indexOf('.') >= 0 ) {
					//  a property (coo.<label>.zones, group.<label>.zones): not a member
					continue;
				}
				labels.add(label);
				ptrs.computeIfAbsent(label, k -> new ArrayList<String>()).add(strip(((us.bringardner.parley.dns.Ptr)rr).getPtr()).toLowerCase(Locale.ROOT));
			}
		}
		if( versions.size() != 1 ) {
			throw new IOException("The catalog "+cat+" has "+(versions.isEmpty() ? "no" : versions.size())+" version property: it needs exactly one, version."+cat+" TXT \""+VERSION+"\"");
		}
		Set<String> ret = new LinkedHashSet<String>();
		for(String label : labels) {
			List<String> list = ptrs.get(label);
			if( list.size() != 1 ) {
				throw new IOException("The catalog "+cat+" lists "+list.size()+" zones at "+label+"."+ZONES+": it needs exactly one");
			}
			if( !ret.add(list.get(0)) ) {
				throw new IOException("The catalog "+cat+" lists "+list.get(0)+" twice");
			}
		}
		return ret;
	}

	static String strip(String name) {
		String n = name == null ? "" : name.trim();
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}
}
