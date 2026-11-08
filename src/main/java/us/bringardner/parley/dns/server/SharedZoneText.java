package us.bringardner.parley.dns.server;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import us.bringardner.parley.files.FileSource;

/**
 * The text of a shared zone ({@code parley.dns.sharedZone}) and of a zone that inherits it, for a
 * program that manages those files: read a shared zone's records (owners relative to the domain,
 * names in the data relative too), check a text as the DNS server checks the file, and write a text
 * for records. Nothing here touches a file: the DNS server only reads zone files (it reads a changed
 * file again), and writing them is the managing program's.
 *
 * @since 2.0.0
 */
public final class SharedZoneText {

	//  the name a text is read under (the .invalid TLD is reserved, RFC 2606)
	private static final String CHECK = "shared-zone.invalid";

	private SharedZoneText() {
	}

	/** A record as a shared zone's file has it: owner relative ({@code @}, {@code www}), data as written. */
	public static final class Record {
		private final String name;
		private final long ttl;
		private final String type;
		private final String data;

		public Record(String name, long ttl, String type, String data) {
			this.name = name;
			this.ttl = ttl;
			this.type = type;
			this.data = data;
		}

		public String getName() {
			return name;
		}

		public long getTtl() {
			return ttl;
		}

		public String getType() {
			return type;
		}

		public String getData() {
			return data;
		}

		/** The same record (TTL aside): names and name data compared without case, text data as is. */
		public boolean same(String n, String t, String d) {
			return name.equalsIgnoreCase(n) && type.equalsIgnoreCase(t)
					&& (textData(type) ? data.trim().equals(d.trim()) : data.trim().equalsIgnoreCase(d.trim()));
		}

		@Override
		public String toString() {
			return name+" "+ttl+" "+type+" "+data;
		}
	}

	/** Types whose data holds no names (copied as is, never made relative). */
	public static boolean textData(String type) {
		switch(type.toUpperCase(Locale.ROOT)) {
		case "TXT": case "SPF": case "HINFO": case "CAA": case "SSHFP": case "DS":
			return true;
		default:
			return false;
		}
	}

	/**
	 * Check a text as the DNS server checks a shared zone's file: a valid zone, its SOA at {@code @},
	 * no {@code $INHERIT}.
	 * @return its SOA serial (unsigned)
	 * @throws IOException naming the line if it isn't a valid shared zone
	 */
	public static long check(String text) throws IOException {
		return check(text, null);
	}

	/**
	 * As {@link #check(String)}, with {@code $INCLUDE} files relative to this folder (the shared zone
	 * file's, as the DNS server reads it).
	 * @param dir the folder (on any file system), or null for the working directory of the default file system
	 */
	public static long check(String text, FileSource dir) throws IOException {
		return Integer.toUnsignedLong(parse(text, dir).getSoa().getSerial());
	}

	/** The records of a shared zone's text, the SOA first, owners and names in the data relative to the domain. */
	public static List<Record> records(String text) throws IOException {
		return records(text, null);
	}

	/**
	 * As {@link #records(String)}, with {@code $INCLUDE} files relative to this folder (the shared
	 * zone file's).
	 * @param dir the folder (on any file system), or null for the working directory of the default file system
	 */
	public static List<Record> records(String text, FileSource dir) throws IOException {
		Zone z = parse(text, dir);
		List<Record> ret = new ArrayList<Record>();
		ret.add(rec(z.getSoa()));
		for(List<us.bringardner.parley.dns.RR> l : z.getRrs()) {
			for(us.bringardner.parley.dns.RR rr : l) {
				if( rr.getType() != us.bringardner.parley.dns.DNS.SOA ) {
					ret.add(rec(rr));
				}
			}
		}
		return ret;
	}

	/**
	 * A shared zone's text for these records (the SOA first), after a header.
	 * @param header comment lines (each starting with ';'), or null
	 */
	public static String text(List<Record> recs, String header) {
		StringBuilder b = new StringBuilder(header == null ? "" : header);
		if( b.length() > 0 && b.charAt(b.length()-1) != '\n' ) {
			b.append('\n');
		}
		for(Record r : recs) {
			b.append(r.name).append('\t').append(r.ttl).append("\tIN\t").append(r.type).append('\t');
			if( r.type.equals("SOA") ) {
				String[] f = r.data.trim().split("\\s+");
				b.append(f[0]).append(' ').append(f[1]).append(" (");
				for(int i=2; i < f.length; i++ ) {
					b.append(' ').append(f[i]);
				}
				b.append(" )");
			} else {
				b.append(r.data.trim());
			}
			b.append('\n');
		}
		return b.toString();
	}

	/**
	 * The zone file text of a domain that inherits the shared zone: a {@code $INHERIT} line and an
	 * SOA like the shared zone's under that domain, serial 1 (the server adds the shared zone's).
	 * @param domain the domain, e.g. example.com
	 * @param sharedText the shared zone's text
	 * @param zoneDir the zone folder, where the DNS server reads the shared zone under the domain's
	 *  name ({@code $INCLUDE} files relative to it), or null for the working directory
	 */
	public static String inheritingZone(String domain, String sharedText, FileSource zoneDir) throws IOException {
		String d = strip(domain.trim()).toLowerCase(Locale.ROOT);
		Zone z;
		try {
			z = new Zone(FileSource.of(zoneDir, d+".txt"), sharedText);
		} catch(IOException e) {
			throw new IOException("The shared zone: "+String.valueOf(e.getMessage()).replace(d+".txt", "its file"), e);
		}
		return Zone.inheritingText(d, z.getSoa());
	}

	/**
	 * The record type as zone files spell it, if records of it can be changed (the DNSSEC types
	 * can't: signing makes them).
	 * @throws IllegalArgumentException if the type is unknown or can't be changed
	 */
	public static String editableType(String type) {
		String t = type == null ? "" : type.trim().toUpperCase(Locale.ROOT);
		for(RecordTypes.Def d : RecordTypes.all()) {
			if( d.name().equals(t) ) {
				if( !d.editable ) {
					throw new IllegalArgumentException(t+" records can't be changed: signing makes them");
				}
				return t;
			}
		}
		throw new IllegalArgumentException("Unknown record type "+type);
	}

	private static Zone parse(String text, FileSource dir) throws IOException {
		Zone z;
		try {
			z = new Zone(FileSource.of(dir, CHECK+".txt"), text);

		} catch(IOException e) {
			throw new IOException("The shared zone: "+String.valueOf(e.getMessage()).replace(CHECK+".txt", "its file"), e);
		}
		if( !strip(z.getName()).equalsIgnoreCase(CHECK) ) {
			throw new IOException("The shared zone's SOA must be at @ (it is at "+z.getName()+")");
		}
		if( z.getInheritFrom() != null ) {
			throw new IOException("The shared zone can't have a $INHERIT line");
		}
		return z;
	}

	private static Record rec(us.bringardner.parley.dns.RR rr) {
		String type = us.bringardner.parley.dns.Utility.TYPENAMES[rr.getType()];
		String data = Zone.rdataText(rr);
		if( !textData(type) ) {
			StringBuilder b = new StringBuilder();
			for(String tok : data.trim().split("\\s+")) {
				if( b.length() > 0 ) {
					b.append(' ');
				}
				b.append(relativeName(tok));
			}
			data = b.toString();
		}
		return new Record(relativeOwner(rr.getName()), rr.getTTL(), type, data);
	}

	/** A name in record data relative to the domain (@ for the domain), others as they are. */
	private static String relativeName(String tok) {
		String l = tok.toLowerCase(Locale.ROOT);
		if( l.equals(CHECK+".") ) {
			return "@";
		}
		if( l.endsWith("."+CHECK+".") ) {
			return tok.substring(0, tok.length()-CHECK.length()-2);
		}
		return tok;
	}

	private static String relativeOwner(String owner) {
		String n = strip(owner);
		if( n.equalsIgnoreCase(CHECK) ) {
			return "@";
		}
		if( n.toLowerCase(Locale.ROOT).endsWith("."+CHECK) ) {
			return n.substring(0, n.length()-CHECK.length()-1);
		}
		return n+".";
	}

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}
}
