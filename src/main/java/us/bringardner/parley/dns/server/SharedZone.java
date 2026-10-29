package us.bringardner.parley.dns.server;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


/**
 * The shared zone ({@code parley.dns.sharedZone}): a zone file written with relative names, whose
 * records every listed domain serves under its own name, and every zone with a {@code $INHERIT}
 * line inherits. {@code @} is the domain, a relative owner ({@code www}, {@code *},
 * {@code _dmarc}) is below it, and relative names in record data ({@code MX 10 mail}) are
 * completed with the domain too; a name with a trailing dot is the same for every domain. Its SOA
 * gives each domain's SOA (its serial is added to an inheriting zone's own).
 * <p>
 * The file is read again when it changes; one that can't be read keeps the version read last.
 */
final class SharedZone {

	//  the name the file is checked under when it is read (the .invalid TLD is reserved, RFC 2606)
	private static final String CHECK = "shared-zone.invalid";

	private final File file;
	private volatile String text;
	private volatile List<String> warnings = Collections.emptyList();
	private volatile String stamp;
	//  the zone read under each domain's name, for the current text
	private final Map<String, Zone> byDomain = new ConcurrentHashMap<String, Zone>();

	SharedZone(File file) {
		this.file = file;
	}

	File getFile() {
		return file;
	}

	/** Whether the file changed since it was read (or was never read). */
	boolean changed() {
		return !stamp(file).equals(stamp);
	}

	/** Whether a version of the file has been read (and can be served). */
	boolean isReady() {
		return text != null;
	}

	/** The load warnings of the version read (e.g. a '*' that isn't the leftmost label). */
	List<String> getWarnings() {
		return warnings;
	}

	/** The file's text as it is now (UTF-8), or null when there is no file. */
	String fileText() throws IOException {
		if( !file.exists() ) {
			return null;
		}
		return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
	}

	/**
	 * Check a text as this shared zone, as {@link #read()} checks the file.
	 * @return its SOA serial (unsigned)
	 * @throws IOException naming the file and line if it isn't a valid shared zone
	 */
	long check(String t) throws IOException {
		Zone z = parse(CHECK, t, file.getAbsoluteFile().getParentFile());
		return Integer.toUnsignedLong(z.getSoa().getSerial());
	}

	/** Read the file at the next {@link #read()} even if its time and length look unchanged. */
	void forget() {
		stamp = null;
	}

	/**
	 * Read the file again if it changed, checking it as a zone.
	 * @return true if a new version was read
	 * @throws IOException if it can't be read or isn't a valid zone (the version read last is kept)
	 */
	synchronized boolean read() throws IOException {
		String s = stamp(file);
		if( s.equals(stamp) ) {
			return false;
		}
		//  Not read again until it changes, even if it fails
		stamp = s;
		String t;
		try {
			t = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
		} catch(IOException e) {
			throw new IOException("Can't read the shared zone "+file+": "+e.getMessage(), e);
		}
		Zone check = parse(CHECK, t, file.getParentFile());
		List<String> w = new ArrayList<String>();
		for(String m : check.getLoadWarnings()) {
			w.add(m.replace(CHECK+".txt", file.getName()));
		}
		text = t;
		warnings = Collections.unmodifiableList(w);
		byDomain.clear();
		return true;
	}

	/**
	 * The shared zone read under a domain's name (for {@link Zone#inherit(Zone, Zone)}): the same
	 * object until the file changes.
	 */
	Zone under(String domain, File zoneDir) throws IOException {
		String t = text;
		if( t == null ) {
			throw new IOException("The shared zone "+file+" has not been read");
		}
		String d = strip(domain).toLowerCase(Locale.ROOT);
		Zone z = byDomain.get(d);
		if( z == null ) {
			z = parse(d, t, zoneDir);
			if( text == t ) {
				byDomain.put(d, z);
			}
		}
		return z;
	}

	private Zone parse(String domain, String t, File dir) throws IOException {
		Zone z;
		try {
			//  read as the text of <domain>.txt: @ and relative names are the domain's
			z = new Zone(new File(dir, domain+".txt"), t);
		} catch(IOException e) {
			String m = String.valueOf(e.getMessage()).replace(domain+".txt", file.getName());
			throw new IOException("The shared zone "+file+": "+m, e);
		}
		if( !strip(z.getName()).equalsIgnoreCase(domain) ) {
			throw new IOException("The shared zone "+file+": its SOA must be at @ (it is at "+z.getName()+")");
		}
		if( z.getInheritFrom() != null ) {
			throw new IOException("The shared zone "+file+" can't have a $INHERIT line");
		}
		return z;
	}

	private static String stamp(File f) {
		return f.exists() ? f.lastModified()+"/"+f.length() : "-";
	}

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}
}
