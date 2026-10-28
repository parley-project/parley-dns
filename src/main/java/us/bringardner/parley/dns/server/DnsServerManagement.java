package us.bringardner.parley.dns.server;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
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
					count(z.getUnsigned()), count(own), z.getSigned() != null, f == null ? null : f.getPath()));
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
	public synchronized void createInheritingZone(String zone, String inheritFrom) throws Exception {
		String name = zone == null ? "" : strip(zone.trim()).toLowerCase(Locale.ROOT);
		String from = inheritFrom == null ? "" : strip(inheritFrom.trim()).toLowerCase(Locale.ROOT);
		if( !DOMAIN.matcher(name).matches() ) {
			throw new IllegalArgumentException("Not a domain name: "+zone);
		}
		if( server.getZone(name) != null ) {
			throw new IllegalArgumentException("Zone "+name+" exists already");
		}
		Zone parent = server.getZone(from);
		if( parent == null ) {
			throw new IllegalArgumentException("Zone "+inheritFrom+" isn't served");
		}
		if( parent.getOwn().getInheritFrom() != null ) {
			throw new IllegalArgumentException("Zone "+from+" inherits from another zone itself");
		}
		File dir = server.getZoneDirectory();
		File file = new File(dir, name+".txt");
		if( file.exists() ) {
			throw new IllegalArgumentException("The zone file "+file+" exists already");
		}
		Soa soa = parent.getOwn().getSoa();
		String text = "; "+name+": the records of "+from+", with this zone's own added or overriding them (by name and type)\n"
				+"$INHERIT "+from+".\n"
				+"@\t"+soa.getTTL()+"\tIN\tSOA\t"+dot(soa.getMname())+" "+dot(soa.getRname())+" ( 1 "
				+soa.getRefreash()+" "+soa.getRetry()+" "+soa.getExpire()+" "+soa.getMinimum()+" )\n";
		File tmp = File.createTempFile("."+name, ".tmp", dir);
		try {
			Files.write(tmp.toPath(), text.getBytes(StandardCharsets.UTF_8));
			Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE);
		} finally {
			tmp.delete();
		}
		server.loadZones();
		if( server.getZone(name) == null ) {
			throw new IllegalStateException("Made "+file+" but the zone didn't load; see the server's errors");
		}
	}

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}

	private static String dot(String n) {
		return n.endsWith(".") ? n : n+".";
	}
}
