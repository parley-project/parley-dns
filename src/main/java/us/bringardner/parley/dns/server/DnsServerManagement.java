package us.bringardner.parley.dns.server;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Soa;
import us.bringardner.parley.dns.Utility;

/** {@link DnsServerMXBean} for a {@link DnsServer}; see {@link DnsServer#registerManagement}. */
class DnsServerManagement implements DnsServerMXBean {

	/** A domain name in lower case: labels of letters, digits and '-' (not at either end) */
	static final java.util.regex.Pattern DOMAIN = java.util.regex.Pattern.compile(
			"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

	private final DnsServer server;

	DnsServerManagement(DnsServer server) {
		this.server = server;
	}

	@Override
	public String getState() {
		return server.isRunning() ? "RUNNING" : "STOPPED";
	}

	@Override
	public long getStarted() {
		return server.getStartedAt();
	}

	@Override
	public int getTcpPort() {
		return server.getTcpPort();
	}

	@Override
	public boolean isRecursionAvailable() {
		return server.isRecursionAvailable();
	}

	@Override
	public String[] getUpdateKeyNames() {
		return server.getUpdateKeyNames().stream().sorted().toArray(String[]::new);
	}

	@Override
	public String getZoneDirectory() {
		File d = server.getZoneDirectory();
		return d == null ? null : d.getPath();
	}

	@Override
	public DnsZoneInfo[] getZones() {
		Map<String, Zone> sorted = new TreeMap<String, Zone>(server.getZones());
		List<DnsZoneInfo> ret = new ArrayList<DnsZoneInfo>();
		for(Zone z : sorted.values()) {
			Zone own = z.getOwn();
			File f = own.getMasterFile();
			ret.add(new DnsZoneInfo(strip(z.getName()), z.isInherited() ? own.getInheritFrom() : null,
					Integer.toUnsignedLong(z.getSoa().getSerial()), Integer.toUnsignedLong(own.getSoa().getSerial()),
					count(z.getUnsigned()), count(own), z.getSigned() != null, f == null || own.isVirtual() ? null : f.getPath()));
		}
		return ret.toArray(new DnsZoneInfo[0]);
	}

	private static int count(Zone z) {
		int ret = 0;
		for(List<RR> l : z.getRrs()) {
			ret += l.size();
		}
		return ret;
	}

	@Override
	public DnsRecordInfo[] getRecords(String zone) {
		Zone z = zone == null ? null : server.getZone(strip(zone).toLowerCase(Locale.ROOT));
		if( z == null ) {
			throw new IllegalArgumentException("No zone "+zone);
		}
		Zone own = z.getOwn();
		Set<String> ownKeys = new HashSet<String>();
		for(List<RR> l : own.getRrs()) {
			for(RR rr : l) {
				ownKeys.add(Zone.recordKey(rr));
			}
		}
		Zone served = z.getUnsigned();
		List<DnsRecordInfo> ret = new ArrayList<DnsRecordInfo>();
		for(List<RR> l : served.getRrs()) {
			for(RR rr : l) {
				ret.add(new DnsRecordInfo(strip(rr.getName()), Utility.TYPENAMES[rr.getType()], rr.getTTL(),
						Zone.rdataText(rr), !ownKeys.contains(Zone.recordKey(rr))));
			}
		}
		ret.sort((a, b) -> {
			int c = a.getName().compareToIgnoreCase(b.getName());
			return c != 0 ? c : a.getType().compareTo(b.getType());
		});
		return ret.toArray(new DnsRecordInfo[0]);
	}

	@Override
	public String[] getErrors() {
		return server.getZoneErrors().toArray(new String[0]);
	}

	@Override
	public void reload() throws Exception {
		server.loadZones();
	}

	@Override
	public void createInheritingZone(String zone) throws Exception {
		//  (the server's lock: every bean of this server, and its reloads, take it)
		synchronized(server) {
			create(zone);
		}
	}

	private void create(String zone) throws Exception {
		String name = zone == null ? "" : strip(zone.trim()).toLowerCase(Locale.ROOT);
		if( !DOMAIN.matcher(name).matches() ) {
			throw new IllegalArgumentException("Not a domain name: "+zone);
		}
		Zone existing = server.getZone(name);
		if( existing != null && existing.getOwn().isVirtual() ) {
			throw new IllegalArgumentException("Zone "+name+" is served already: it is a listed domain, served from"
					+" the shared zone; its zone file is written when one of its records is changed");
		}
		if( existing != null ) {
			throw new IllegalArgumentException("Zone "+name+" exists already");
		}
		SharedZone shared = server.getSharedZone();
		if( shared == null ) {
			throw new IllegalArgumentException(DnsServer.PROP_SHARED_ZONE+" is not set: there is no shared zone to inherit");
		}
		if( !shared.isReady() ) {
			throw new IllegalArgumentException("The shared zone "+shared.getFile()+" can't be read; see the server's errors");
		}
		File dir = server.getZoneDirectory();
		File file = new File(dir, name+".txt");
		if( file.exists() ) {
			throw new IllegalArgumentException("The zone file "+file+" exists already");
		}
		File journal = new File(file.getPath()+".jnl");
		if( journal.exists() ) {
			//  It would be replayed into the new zone (an earlier zone of this name, made the same way)
			throw new IllegalArgumentException("An old journal of the zone is there: "+journal+"; move it away first");
		}
		Soa soa = shared.under(name, dir).getSoa();
		String text = Zone.inheritingText(name, soa);
		File tmp = File.createTempFile("."+name, ".tmp", dir);
		try {
			Files.write(tmp.toPath(), text.getBytes(StandardCharsets.UTF_8));
			//  A link appears whole and fails if the file is there by now (a move would replace it)
			Files.createLink(file.toPath(), tmp.toPath());
		} catch(java.nio.file.FileAlreadyExistsException e) {
			throw new IllegalArgumentException("The zone file "+file+" exists already");
		} finally {
			tmp.delete();
		}
		try {
			server.loadZones();
		} catch(Exception e) {
			file.delete();
			throw e;
		}
		if( server.getZone(name) == null ) {
			file.delete();
			throw new IllegalStateException("Made "+file+" but the zone didn't load (removed again); see the server's errors");
		}
	}

	@Override
	public String getSharedZoneFile() {
		SharedZone s = server.getSharedZone();
		return s == null ? null : s.getFile().getPath();
	}

	@Override
	public String getSharedZoneText() throws Exception {
		SharedZone s = requireShared();
		String t = s.fileText();
		if( t == null ) {
			throw new IllegalStateException("The shared zone's file "+s.getFile()+" doesn't exist");
		}
		return t;
	}

	@Override
	public void setSharedZoneText(String text, String expected) throws Exception {
		//  (the server's lock, as for createInheritingZone)
		synchronized(server) {
			writeShared(text, expected);
		}
	}

	private SharedZone requireShared() {
		SharedZone s = server.getSharedZone();
		if( s == null ) {
			throw new IllegalStateException(DnsServer.PROP_SHARED_ZONE+" is not set: there is no shared zone");
		}
		return s;
	}

	private void writeShared(String text, String expected) throws Exception {
		SharedZone s = requireShared();
		if( text == null || text.trim().isEmpty() ) {
			throw new IllegalArgumentException("The shared zone's text is empty");
		}
		String t = lines(text);
		if( !t.endsWith("\n") ) {
			t += "\n";
		}
		String now = s.fileText();
		if( expected != null && (now == null || !lines(now).equals(lines(expected))) ) {
			throw new IllegalStateException("The shared zone was changed since it was read: read it again and make the change again");
		}
		long serial;
		try {
			serial = s.check(t);
		} catch(java.io.IOException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		if( now != null ) {
			long old = -1;
			try {
				old = s.check(now);
			} catch(java.io.IOException e) {
				//  the file there isn't valid: any serial replaces it
			}
			if( old >= 0 && serial <= old ) {
				throw new IllegalArgumentException("Raise the SOA serial: it is "+serial+" and must be higher than "+old
						+", so secondaries see the change");
			}
		}
		File f = s.getFile().getAbsoluteFile();
		File dir = f.getParentFile();
		File tmp = File.createTempFile("."+f.getName(), ".tmp", dir);
		try {
			Files.write(tmp.toPath(), t.getBytes(StandardCharsets.UTF_8));
			if( f.exists() ) {
				try {
					Files.setPosixFilePermissions(tmp.toPath(), Files.getPosixFilePermissions(f.toPath()));
				} catch(UnsupportedOperationException e) {
					//  not a POSIX file system
				}
				Files.copy(f.toPath(), new File(dir, f.getName()+".previous").toPath(),
						java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
			}
			Files.move(tmp.toPath(), f.toPath(), java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
		} finally {
			tmp.delete();
		}
		//  (read even if an edit in the same millisecond left its time and length as they were)
		s.forget();
		server.loadZones();
	}

	private static String lines(String t) {
		return t.replace("\r\n", "\n").replace('\r', '\n');
	}

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}

}
