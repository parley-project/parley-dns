package us.bringardner.parley.dns.server;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;

import us.bringardner.parley.core.NamedThreadFactory;
import us.bringardner.parley.dns.DnsBaseClass;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Soa;
import us.bringardner.parley.dns.Tsig;
import us.bringardner.parley.files.FileSource;

/**
 * The zones this server is a secondary for: kept up to date by transferring
 * them from a primary (AXFR over TCP, signed with a TSIG key when one is set),
 * at start, when the primary sends a NOTIFY, and when the zone's SOA refresh
 * time passes.
 * <p>
 * A transferred zone is written as an ordinary zone file in the zone folder
 * (a temporary file first, then renamed over the old one), so the server loads
 * it as it loads any zone, and serves it again after a restart without waiting
 * for a transfer. The zone's SOA timers are the transferred SOA's:
 * <ul>
 * <li>refresh: ask the primary whether its serial is newer, and transfer if it is;</li>
 * <li>retry: when that failed, ask again after this long;</li>
 * <li>expire: with no successful contact for this long, the zone is not served (SERVFAIL).</li>
 * </ul>
 * A zone with no file yet is not served (SERVFAIL) until its first transfer.
 * <p>
 * With a catalog zone (RFC 9432, see {@link CatalogZone}) the zones to keep are also the members of that
 * catalog, which is transferred like any zone of this server and read each time it is current: a member
 * not kept yet is added and transferred, and a member the catalog no longer lists (one that came from
 * the catalog, not from the list of zones) stops being served and its file is renamed to
 * <code>&lt;zone&gt;.txt.removed</code>, which is not loaded at a restart. A catalog that is broken, or that
 * lists no zone when we keep some from it, changes nothing.
 */
public class SecondaryZones extends DnsBaseClass {

	/** Where a secondary zone stands. */
	public enum State {
		/** Never transferred, no zone file: not served */
		PENDING,
		/** Served */
		SERVING,
		/** The primary has not been reached for the SOA's expire time: not served */
		EXPIRED
	}

	/** One zone this server is a secondary for. */
	public static final class Entry {
		private final String name;
		private volatile State state = State.PENDING;
		private volatile long lastSuccess;
		private volatile long nextCheck;
		private volatile boolean running;
		private volatile String lastError;
		/** the catalog zone itself */
		private final boolean catalog;
		/** came from the catalog's member list, not from the list of zones */
		private final boolean fromCatalog;

		Entry(String name) {
			this(name, false, false);
		}

		Entry(String name, boolean catalog, boolean fromCatalog) {
			this.name = name;
			this.catalog = catalog;
			this.fromCatalog = fromCatalog;
		}

		/** Is this the catalog zone? */
		public boolean isCatalog() {
			return catalog;
		}

		/** Was this zone added from the catalog (it is dropped when the catalog drops it)? */
		public boolean isFromCatalog() {
			return fromCatalog;
		}

		public String getName() {
			return name;
		}

		public State getState() {
			return state;
		}

		/** The last time the primary was reached and the zone was current (ms since the epoch), 0 if never. */
		public long getLastSuccess() {
			return lastSuccess;
		}

		/** The reason the last attempt failed, or null. */
		public String getLastError() {
			return lastError;
		}
	}

	/** The server these zones are in. */
	public interface Host {
		/** The folder the zone files are in. */
		FileSource getZoneDir();

		/** The zone being served, or null. */
		Zone getZone(String zoneName);

		/** Load the zone files again and serve what they hold. */
		void reloadZones() throws IOException;
	}

	/** Retry time for a zone we have no SOA for yet, in seconds. */
	static final int DEFAULT_RETRY = 60;
	/** Refresh time for a zone we have no SOA for, in seconds. */
	static final int DEFAULT_REFRESH = 3600;

	private final Host host;
	private final ZoneTransferClient client;
	private final InetSocketAddress primary;
	private final Tsig.Key key;
	private final Map<String, Entry> zones = new ConcurrentHashMap<String, Entry>();
	private final String catalogName;
	private final ExecutorService worker = Executors.newSingleThreadExecutor(new NamedThreadFactory("SecondaryZones"));

	/**
	 * @param zoneNames the zones to keep, separated by commas or spaces
	 * @param primary where the zones come from
	 * @param key the TSIG key to sign requests with and to check answers by, or null
	 */
	public SecondaryZones(Host host, String zoneNames, InetSocketAddress primary, Tsig.Key key, int fudge, int timeoutMs) {
		this(host, zoneNames, null, primary, key, fudge, timeoutMs);
	}

	/**
	 * @param zoneNames the zones to keep, separated by commas or spaces; may be empty when there is a catalog zone
	 * @param catalogZone the primary's catalog zone, whose members are kept too, or null
	 * @param primary where the zones come from
	 * @param key the TSIG key to sign requests with and to check answers by, or null
	 */
	public SecondaryZones(Host host, String zoneNames, String catalogZone, InetSocketAddress primary, Tsig.Key key, int fudge, int timeoutMs) {
		this.host = host;
		this.primary = primary;
		this.key = key;
		this.client = new ZoneTransferClient(primary, key, fudge, timeoutMs);
		for(String z : (zoneNames == null ? "" : zoneNames).trim().split("[,\\s]+")) {
			if( !z.isEmpty() ) {
				String n = ZoneTransferClient.strip(z).toLowerCase(Locale.ROOT);
				zones.put(n, new Entry(n));
			}
		}
		if( catalogZone != null && !catalogZone.trim().isEmpty() ) {
			catalogName = ZoneTransferClient.strip(catalogZone).toLowerCase(Locale.ROOT);
			zones.put(catalogName, new Entry(catalogName, true, false));
		} else {
			catalogName = null;
		}
		if( zones.isEmpty() ) {
			throw new IllegalArgumentException("No secondary zone named");
		}
	}

	/** A zone name as this class keeps it: lower case, no final dot. */
	static String normalize(String name) {
		return ZoneTransferClient.strip(name).toLowerCase(Locale.ROOT);
	}

	/** The catalog zone's name, or null. */
	public String getCatalogName() {
		return catalogName;
	}

	public List<Entry> getEntries() {
		return Collections.unmodifiableList(new ArrayList<Entry>(new java.util.TreeMap<String, Entry>(zones).values()));
	}

	/** The secondary zone with exactly this name, or null. */
	public Entry get(String zoneName) {
		return zoneName == null ? null : zones.get(ZoneTransferClient.strip(zoneName).toLowerCase(Locale.ROOT));
	}

	/** The secondary zone the name is in (the nearest one above it), or null. */
	public Entry find(String name) {
		String n = ZoneTransferClient.strip(name).toLowerCase(Locale.ROOT);
		for( ; n != null && !n.isEmpty(); ) {
			Entry e = zones.get(n);
			if( e != null ) {
				return e;
			}
			int dot = n.indexOf('.');
			n = dot < 0 ? null : n.substring(dot+1);
		}
		return null;
	}

	/** Is this a name in a secondary zone that is not being served now (never transferred, or expired)? */
	public boolean isUnavailable(String name) {
		Entry e = find(name);
		return e != null && e.state != State.SERVING;
	}

	/** Is this address the primary's? Only it may send a NOTIFY. */
	public boolean isPrimary(InetAddress address) {
		return address != null && address.equals(primary.getAddress());
	}

	public InetSocketAddress getPrimary() {
		return primary;
	}

	/** The key requests are signed with, or null. */
	public Tsig.Key getKey() {
		return key;
	}

	/**
	 * Before the zone files are loaded: a zone with a file is served as it is
	 * (and checked soon); one without is transferred now, so a first start
	 * serves it. A transfer that fails leaves the zone pending, and
	 * {@link #maintain} retries it.
	 */
	public void start() {
		long now = System.currentTimeMillis();
		for(Entry e : new ArrayList<Entry>(zones.values())) {
			boolean hasFile = false;
			try {
				hasFile = zoneFile(e.name).exists();
			} catch(IOException ex) {
				logError("Can't look for the zone file of "+e.name, ex);
			}
			if( hasFile ) {
				//  Served at once. The time to expire counts from now: we don't know when the file was current.
				e.state = State.SERVING;
				e.lastSuccess = now;
				e.nextCheck = now;
			} else {
				try {
					transferAndStore(e, false, false);
				} catch(IOException ex) {
					fail(e, ex);
				}
			}
		}
	}

	/**
	 * A NOTIFY from the primary (RFC 1996): check the zone now, in the background.
	 */
	public void notified(Entry e) {
		schedule(e);
	}

	/**
	 * One round: expire the zones the primary has not answered for too long,
	 * and check those whose time has come, in the background.
	 */
	public void maintain() {
		long now = System.currentTimeMillis();
		for(Entry e : new ArrayList<Entry>(zones.values())) {
			if( e.state == State.SERVING && now - e.lastSuccess > expireMillis(e) ) {
				e.state = State.EXPIRED;
				logError("Zone "+e.name+" expired: the primary "+primary+" has not been reached for "+((now - e.lastSuccess)/1000)
						+" seconds (its SOA expire time is "+(expireMillis(e)/1000)+"); it is not served until a transfer succeeds");
			}
			if( now >= e.nextCheck ) {
				schedule(e);
			}
		}
	}

	private void schedule(Entry e) {
		if( e.running ) {
			return;
		}
		e.running = true;
		try {
			worker.execute(() -> {
				try {
					check(e);
				} catch(Throwable t) {
					fail(e, t);
				} finally {
					e.running = false;
				}
			});
		} catch(RejectedExecutionException ex) {
			//  shut down (the server is stopping)
			e.running = false;
		}
	}

	/** Ask the primary for its serial; transfer if it is newer than ours (or if we have no zone). */
	void check(Entry e) throws IOException {
		Zone mine = host.getZone(e.name);
		int theirs = client.fetchSerial(e.name);
		if( mine != null && e.state != State.PENDING && !serialNewer(theirs, mine.getSoa().getSerial()) ) {
			succeed(e, mine.getSoa());
			log(() -> "Zone "+e.name+" is current (serial "+Integer.toUnsignedString(theirs)+")");
			if( e.catalog ) {
				applyCatalog(mine.getRrs().stream().flatMap(List::stream).collect(Collectors.toList()), true);
			}
			return;
		}
		transferAndStore(e, true, true);
	}

	private void transferAndStore(Entry e, boolean reload, boolean schedule) throws IOException {
		ZoneTransferClient.Transfer t = client.transfer(e.name);
		store(e.name, t);
		Soa soa = t.getSoa();
		if( reload ) {
			host.reloadZones();
		}
		succeed(e, soa);
		final int n = t.getRecords().size();
		log(() -> "Zone "+e.name+" transferred from "+primary+": serial "+Integer.toUnsignedString(soa.getSerial())+", "+n+" records");
		if( e.catalog ) {
			applyCatalog(t.getRecords(), schedule);
		}
	}

	/**
	 * Bring the zones we keep from the catalog in line with its members. A catalog that is broken is
	 * not used (the zones stay as they are), and neither is one with no member when we keep some from
	 * the catalog: an empty catalog is most likely a mistake at the primary, and acting on it would
	 * drop every zone (RFC 9432 section 6).
	 *
	 * @param schedule check the added zones now, in the background (not before the zone files are first loaded)
	 */
	void applyCatalog(List<RR> records, boolean schedule) {
		Set<String> members;
		try {
			members = CatalogZone.members(catalogName, records);
		} catch(IOException ex) {
			logError("The catalog zone "+catalogName+" can't be used, the zones stay as they are: "+ex.getMessage());
			return;
		}
		Set<String> kept = new LinkedHashSet<String>();
		for(Entry e : zones.values()) {
			if( e.fromCatalog ) {
				kept.add(e.name);
			}
		}
		if( members.isEmpty() && !kept.isEmpty() ) {
			logError("The catalog zone "+catalogName+" lists no zone, the "+kept.size()+" zones kept from it stay as they are");
			return;
		}
		boolean removed = false;
		for(String name : kept) {
			if( !members.contains(name) ) {
				removed |= drop(zones.remove(name));
			}
		}
		for(String name : members) {
			if( zones.containsKey(name) ) {
				continue;
			}
			if( host.getZone(name) != null && !writtenHere(name) ) {
				logError("The catalog zone "+catalogName+" lists "+name+", which this server already serves from its own zone file: not taken from the primary");
				continue;
			}
			Entry e = new Entry(name, false, true);
			if( host.getZone(name) != null ) {
				//  after a restart: the file a transfer wrote is served at once (and checked soon), like the zones in the list
				e.state = State.SERVING;
				e.lastSuccess = System.currentTimeMillis();
				e.nextCheck = e.lastSuccess;
			}
			zones.put(name, e);
			log(() -> "Zone "+name+" is in the catalog zone "+catalogName+": keeping it as a secondary zone");
			if( schedule ) {
				schedule(e);
			}
		}
		if( removed ) {
			try {
				host.reloadZones();
			} catch(IOException ex) {
				logError("Can't load the zones again after dropping zones the catalog zone "+catalogName+" no longer lists", ex);
			}
		}
	}

	/**
	 * Is the zone's file one a transfer wrote (see {@link #store}), as after a restart, and not a zone
	 * of this server's own? Only the first line tells.
	 */
	private boolean writtenHere(String zoneName) {
		try(java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(zoneFile(zoneName).getInputStream(), StandardCharsets.UTF_8))) {
			String first = r.readLine();
			return first != null && first.startsWith(headerStart(zoneName));
		} catch(IOException e) {
			return false;
		}
	}

	private static String headerStart(String zoneName) {
		return "; "+zoneName+": a secondary zone, transferred from ";
	}

	/** Stop keeping a zone the catalog dropped: its file becomes <zone>.txt.removed, which is not loaded. */
	private boolean drop(Entry e) {
		if( e == null ) {
			return false;
		}
		try {
			FileSource f = zoneFile(e.name);
			if( f.exists() ) {
				FileSource moved = host.getZoneDir().getChild(e.name+".txt.removed");
				if( !f.renameTo(moved, true) ) {
					logError("Zone "+e.name+" is no longer in the catalog zone "+catalogName+", but its file can't be renamed to "+moved.getName());
					return false;
				}
			}
			log(() -> "Zone "+e.name+" is no longer in the catalog zone "+catalogName+": not served now, its file is "+e.name+".txt.removed");
			return true;
		} catch(IOException ex) {
			logError("Can't drop the zone "+e.name+" the catalog zone "+catalogName+" no longer lists", ex);
			return false;
		}
	}

	private void succeed(Entry e, Soa soa) {
		long now = System.currentTimeMillis();
		e.state = State.SERVING;
		e.lastSuccess = now;
		e.lastError = null;
		e.nextCheck = now + Math.max(1, soa.getRefreash()) * 1000L;
	}

	private void fail(Entry e, Throwable t) {
		long now = System.currentTimeMillis();
		Zone mine = host.getZone(e.name);
		int retry = mine != null ? mine.getSoa().getRetry() : DEFAULT_RETRY;
		e.lastError = String.valueOf(t.getMessage());
		e.nextCheck = now + Math.max(1, retry) * 1000L;
		logError("Zone "+e.name+": transfer from "+primary+" failed ("+e.lastError+"); "
				+(e.state == State.SERVING ? "still serving the zone we have, " : "")+"trying again in "+Math.max(1, retry)+" seconds");
	}

	private long expireMillis(Entry e) {
		Zone mine = host.getZone(e.name);
		return mine != null ? Math.max(1, mine.getSoa().getExpire()) * 1000L : Long.MAX_VALUE;
	}

	/** Is serial a newer than b (RFC 1982 serial number arithmetic)? */
	static boolean serialNewer(int a, int b) {
		return a != b && (a - b) > 0;
	}

	private FileSource zoneFile(String zoneName) throws IOException {
		return host.getZoneDir().getChild(zoneName+".txt");
	}

	/**
	 * Write the zone as a zone file: to a temporary file first and then renamed
	 * over the old one, so a reload never sees half a zone. Every record has its
	 * absolute owner name, TTL and class.
	 */
	void store(String zoneName, ZoneTransferClient.Transfer t) throws IOException {
		StringBuilder text = new StringBuilder();
		text.append(headerStart(zoneName)).append(primary)
		.append(" (serial ").append(Integer.toUnsignedString(t.getSoa().getSerial())).append(").\n")
		.append("; Changes are made at the primary: this file is written again by each transfer.\n");
		text.append(Zone.recordLine(t.getSoa())).append('\n');
		for(RR rr : t.getRecords()) {
			text.append(Zone.recordLine(rr)).append('\n');
		}
		FileSource dest = zoneFile(zoneName);
		FileSource temp = host.getZoneDir().getChild("."+zoneName+".txt.transfer");
		try(OutputStream out = temp.getOutputStream()) {
			out.write(text.toString().getBytes(StandardCharsets.UTF_8));
			out.flush();
		}
		if( !temp.renameTo(dest, true) ) {
			try {
				temp.delete();
			} catch(IOException ignore) {
				//  the rename failure is the news
			}
			throw new IOException("Can't replace "+dest+" with the transferred zone");
		}
	}

	/** Stop the background checks. */
	public void shutdown() {
		worker.shutdownNow();
	}

	/** The zone names, for the log. */
	@Override
	public String toString() {
		return "secondary for "+new java.util.TreeSet<String>(zones.keySet())+(catalogName == null ? "" : " and the zones in the catalog zone "+catalogName)+" from "+primary+(key == null ? "" : " (TSIG key "+key.getName()+")");
	}
}
