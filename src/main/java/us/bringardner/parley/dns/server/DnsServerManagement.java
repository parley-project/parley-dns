package us.bringardner.parley.dns.server;

import java.io.File;
import java.io.IOException;
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
		//  the SOA (the zone's own: an inheriting zone's serial is its own plus the shared zone's)
		Soa soa = served.getSoa();
		ret.add(new DnsRecordInfo(strip(z.getName()), "SOA", soa.getTTL(), Zone.rdataText(soa), false));
		for(List<RR> l : served.getRrs()) {
			for(RR rr : l) {
				ret.add(new DnsRecordInfo(strip(rr.getName()), Utility.TYPENAMES[rr.getType()], rr.getTTL(),
						Zone.rdataText(rr), !ownKeys.contains(Zone.recordKey(rr))));
			}
		}
		ret.subList(1, ret.size()).sort((a, b) -> {
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
	public DnsRecordType[] getRecordTypes() {
		List<DnsRecordType> ret = new ArrayList<DnsRecordType>();
		for(RecordTypes.Def d : RecordTypes.all()) {
			ret.add(new DnsRecordType(d.name(), d.example, d.editable));
		}
		return ret.toArray(new DnsRecordType[0]);
	}

	@Override
	public DnsRecordInfo[] getSharedRecords() throws Exception {
		SharedZone s = requireShared();
		List<DnsRecordInfo> ret = new ArrayList<DnsRecordInfo>();
		for(SharedZone.Rec r : current(s)) {
			ret.add(new DnsRecordInfo(r.name, r.type, r.ttl, r.data, false));
		}
		return ret.toArray(new DnsRecordInfo[0]);
	}

	@Override
	public void addSharedRecords(String name, String type, long ttl, String[] values) throws Exception {
		String n = sharedName(name);
		String t = editableType(type);
		if( t.equals("SOA") ) {
			throw new IllegalArgumentException("The shared zone has one SOA: change it instead");
		}
		List<String> add = new ArrayList<String>();
		for(String v : values == null ? new String[0] : values) {
			if( v != null && !v.trim().isEmpty() ) {
				add.add(v.trim());
			}
		}
		if( add.isEmpty() ) {
			throw new IllegalArgumentException("No value to add");
		}
		editShared(recs -> {
			for(String v : add) {
				boolean have = false;
				for(SharedZone.Rec r : recs) {
					have |= r.same(n, t, v);
				}
				if( !have ) {
					recs.add(after(recs, n), new SharedZone.Rec(n, ttl, t, v));
				}
			}
			setTtl(recs, n, t, ttl);
		});
	}

	@Override
	public void changeSharedRecord(String name, String type, String data, String newName, String newType, long ttl, String newData) throws Exception {
		String n = sharedName(name);
		String nn = sharedName(newName);
		String nt = editableType(newType);
		String t = type == null ? "" : type.trim().toUpperCase(Locale.ROOT);
		if( newData == null || newData.trim().isEmpty() ) {
			throw new IllegalArgumentException("The record needs data");
		}
		if( t.equals("SOA") != nt.equals("SOA") || (nt.equals("SOA") && !nn.equals("@")) ) {
			throw new IllegalArgumentException("The SOA stays the SOA, at @");
		}
		String nd = newData.trim();
		editShared(recs -> {
			int i = find(recs, n, t, data);
			recs.remove(i);
			boolean have = false;
			for(SharedZone.Rec r : recs) {
				have |= r.same(nn, nt, nd);
			}
			if( !have ) {
				recs.add(nt.equals("SOA") ? 0 : n.equalsIgnoreCase(nn) ? i : after(recs, nn), new SharedZone.Rec(nn, ttl, nt, nd));
			}
			setTtl(recs, nn, nt, ttl);
		});
	}

	@Override
	public void deleteSharedRecord(String name, String type, String data) throws Exception {
		String n = sharedName(name);
		String t = type == null ? "" : type.trim().toUpperCase(Locale.ROOT);
		if( t.equals("SOA") ) {
			throw new IllegalArgumentException("The shared zone's SOA can't be deleted");
		}
		editShared(recs -> recs.remove(find(recs, n, t, data)));
	}

	private static int find(List<SharedZone.Rec> recs, String name, String type, String data) {
		for(int i=0; i < recs.size(); i++ ) {
			if( recs.get(i).same(name, type, data == null ? "" : data) ) {
				return i;
			}
		}
		throw new IllegalStateException("The shared zone has no record "+name+" "+type+" "+data+" (changed meanwhile? read it again)");
	}

	/** Where a record of this name goes: after the last record of the name, or at the end. */
	private static int after(List<SharedZone.Rec> recs, String name) {
		for(int i=recs.size()-1; i > 0; i-- ) {
			if( recs.get(i).name.equalsIgnoreCase(name) ) {
				return i+1;
			}
		}
		return recs.size();
	}

	private static void setTtl(List<SharedZone.Rec> recs, String name, String type, long ttl) {
		for(int i=0; i < recs.size(); i++ ) {
			SharedZone.Rec r = recs.get(i);
			if( r.name.equalsIgnoreCase(name) && r.type.equals(type) && r.ttl != ttl ) {
				recs.set(i, new SharedZone.Rec(r.name, ttl, r.type, r.data));
			}
		}
	}

	/** A shared zone owner: @ for the domain, or a name below it, never absolute. */
	private static String sharedName(String name) {
		String n = name == null ? "" : name.trim();
		if( n.isEmpty() || n.equals("@") ) {
			return "@";
		}
		if( n.endsWith(".") ) {
			throw new IllegalArgumentException("Names in the shared zone are relative to each domain: "+n
					+" ends with a dot (write www, not www.example.com.)");
		}
		return n.toLowerCase(Locale.ROOT);
	}

	private static String editableType(String type) {
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

	private SharedZone requireShared() {
		SharedZone s = server.getSharedZone();
		if( s == null ) {
			throw new IllegalStateException(DnsServer.PROP_SHARED_ZONE+" is not set: there is no shared zone");
		}
		return s;
	}

	private static List<SharedZone.Rec> current(SharedZone s) throws IOException {
		String t = s.fileText();
		if( t == null ) {
			throw new IllegalStateException("The shared zone's file "+s.getFile()+" doesn't exist");
		}
		try {
			return s.records(t);
		} catch(IOException e) {
			throw new IllegalStateException(e.getMessage()+" (fix the file by hand)", e);
		}
	}

	/**
	 * Change the shared zone's records and write its file: the serial is raised past the file's
	 * (unless the change set a higher one), the text is checked, the file replaced whole (the one
	 * it replaces kept as file.previous) and the zones loaded again, so it is served at once.
	 */
	private void editShared(java.util.function.Consumer<List<SharedZone.Rec>> change) throws Exception {
		//  (the server's lock, as for createInheritingZone)
		synchronized(server) {
			SharedZone s = requireShared();
			List<SharedZone.Rec> recs = new ArrayList<SharedZone.Rec>(current(s));
			long old = serial(recs.get(0));
			change.accept(recs);
			SharedZone.Rec soa = recs.get(0);
			if( serial(soa) <= old ) {
				String[] f = soa.data.trim().split("\\s+");
				f[2] = Long.toString(old+1 > 0xFFFFFFFFL ? 1 : old+1);
				recs.set(0, new SharedZone.Rec(soa.name, soa.ttl, soa.type, String.join(" ", f)));
			}
			String t = SharedZone.text(recs);
			try {
				s.check(t);
			} catch(IOException e) {
				throw new IllegalArgumentException(explain(e.getMessage(), recs), e);
			}
			write(s, t);
		}
	}

	private static long serial(SharedZone.Rec soa) {
		String[] f = soa.data.trim().split("\\s+");
		try {
			return f.length < 3 ? -1 : Long.parseLong(f[2]);
		} catch(NumberFormatException e) {
			throw new IllegalArgumentException("The SOA's serial isn't a number: "+f[2]);
		}
	}

	/** A check's error, naming the record of the line it gives rather than the line of a file nobody has seen. */
	private static String explain(String message, List<SharedZone.Rec> recs) {
		java.util.regex.Matcher m = java.util.regex.Pattern.compile("at line (\\d+): (.*)", java.util.regex.Pattern.DOTALL).matcher(String.valueOf(message));
		if( m.find() ) {
			int i = Integer.parseInt(m.group(1)) - SharedZone.HEADER.split("\n").length - 1;
			if( i >= 0 && i < recs.size() ) {
				SharedZone.Rec r = recs.get(i);
				return "Not a valid record: "+r.name+" "+r.type+" "+r.data+" ("+m.group(2).trim()+")";
			}
		}
		return message;
	}

	private void write(SharedZone s, String t) throws Exception {
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

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}

}
