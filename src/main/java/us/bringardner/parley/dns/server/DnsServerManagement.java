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
	public String getSharedZoneFile() {
		SharedZone s = server.getSharedZone();
		//  absolute: a management tool elsewhere resolves it against its own working directory otherwise
		return s == null ? null : s.getFile().getAbsolutePath();
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
		for(SharedZoneText.Record r : current(s)) {
			ret.add(new DnsRecordInfo(r.getName(), r.getType(), r.getTtl(), r.getData(), false));
		}
		return ret.toArray(new DnsRecordInfo[0]);
	}

	private SharedZone requireShared() {
		SharedZone s = server.getSharedZone();
		if( s == null ) {
			throw new IllegalStateException(DnsServer.PROP_SHARED_ZONE+" is not set: there is no shared zone");
		}
		return s;
	}

	private static List<SharedZoneText.Record> current(SharedZone s) throws IOException {
		File f = s.getFile();
		if( !f.exists() ) {
			throw new IllegalStateException("The shared zone's file "+f+" doesn't exist");
		}
		try {
			return SharedZoneText.records(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8), f.getAbsoluteFile().getParentFile());
		} catch(IOException e) {
			throw new IllegalStateException(e.getMessage()+" ("+f+")", e);
		}
	}

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}

}
