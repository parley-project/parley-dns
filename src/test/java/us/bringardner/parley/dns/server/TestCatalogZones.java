package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.Writer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.DnsTransport;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.TestFiles;
import us.bringardner.parley.dns.resolve.QueryData;
import us.bringardner.parley.files.FileSource;

/**
 * Catalog zones (RFC 9432): the zone a primary makes from the zones it serves, the secondary that keeps
 * every zone the catalog lists, and what happens when a zone is added, removed, or the catalog is broken.
 * The primary a secondary reads from is a real DnsServer answering over a loopback socket.
 */
public class TestCatalogZones {

	@TempDir
	static Path tmp;

	private static final String CATALOG = "catalog.test";
	private static final int TCP = -1;

	private final List<AutoCloseable> open = new ArrayList<AutoCloseable>();
	private int folders;
	private static final java.util.Set<String> SET_HERE = new java.util.HashSet<>();

	private FileSource folder() throws IOException {
		return TestFiles.newFolder(tmp, "catalog"+(folders++));
	}

	private static void write(FileSource f, String text) throws IOException {
		try(Writer w = TestFiles.writer(f)) {
			w.write(text);
		}
	}

	private static String zoneText(String name, int serial) {
		return "$TTL 300\n@\tIN\tSOA\tns1."+name+". postmaster."+name+". ( "+serial+" 3600 1800 1209600 300 )\n"
				+"\t\tNS\tns1."+name+".\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"www\tIN\tA\t10.0.0.80\n";
	}

	private <T extends AutoCloseable> T track(T c) {
		open.add(c);
		return c;
	}

	@AfterEach
	public void cleanup() throws Exception {
		for(int i=open.size()-1; i >= 0; i--) {
			open.get(i).close();
		}
		open.clear();
		for(String n : SET_HERE) {
			System.clearProperty(n);
		}
		SET_HERE.clear();
	}

	private static List<RR> records(Zone z) {
		return z.getRrs().stream().flatMap(List::stream).collect(Collectors.toList());
	}

	private static Set<String> set(String... names) {
		return new TreeSet<String>(List.of(names));
	}

	// ---------------------------------------------------------------- the catalog's text

	@Test
	public void theCatalogListsItsMembersAndReadsBack() throws Exception {
		String text = CatalogZone.text(set("b.test", "a.test", "c.sub.test"), 77);
		Zone z = new Zone(folder().getChild(CATALOG+".txt"), text);
		assertEquals(77, z.getSoa().getSerial());
		assertEquals(set("a.test", "b.test", "c.sub.test"), CatalogZone.members(CATALOG, records(z)));
	}

	@Test
	public void aMembersLabelIsTheSameEveryTime() {
		assertEquals(CatalogZone.label("example.com"), CatalogZone.label("Example.COM."));
		assertNotEquals(CatalogZone.label("example.com"), CatalogZone.label("example.org"));
	}

	@Test
	public void aCatalogWithoutTheVersionIsBroken() throws Exception {
		String text = CatalogZone.text(set("a.test"), 1).replace("version\tIN\tTXT\t\"2\"\n", "");
		Zone z = new Zone(folder().getChild(CATALOG+".txt"), text);
		assertThrows(IOException.class, () -> CatalogZone.members(CATALOG, records(z)));
	}

	@Test
	public void aCatalogOfAnotherVersionIsBroken() throws Exception {
		String text = CatalogZone.text(set("a.test"), 1).replace("TXT\t\"2\"", "TXT\t\"1\"");
		Zone z = new Zone(folder().getChild(CATALOG+".txt"), text);
		assertThrows(IOException.class, () -> CatalogZone.members(CATALOG, records(z)));
	}

	@Test
	public void twoLabelsForOneZoneIsBroken() throws Exception {
		String text = CatalogZone.text(set("a.test"), 1)+"other.zones\tIN\tPTR\ta.test.\n";
		Zone z = new Zone(folder().getChild(CATALOG+".txt"), text);
		assertThrows(IOException.class, () -> CatalogZone.members(CATALOG, records(z)));
	}

	@Test
	public void twoZonesAtOneLabelIsBroken() throws Exception {
		String text = CatalogZone.text(set("a.test"), 1)+CatalogZone.label("a.test")+".zones\tIN\tPTR\tb.test.\n";
		Zone z = new Zone(folder().getChild(CATALOG+".txt"), text);
		assertThrows(IOException.class, () -> CatalogZone.members(CATALOG, records(z)));
	}

	@Test
	public void propertiesOfAMemberAreNotMembers() throws Exception {
		String text = CatalogZone.text(set("a.test"), 1)+"group."+CatalogZone.label("a.test")+".zones\tIN\tTXT\t\"mail\"\n"
				+"coo."+CatalogZone.label("a.test")+".zones\tIN\tPTR\tother.catalog.\n";
		Zone z = new Zone(folder().getChild(CATALOG+".txt"), text);
		assertEquals(set("a.test"), CatalogZone.members(CATALOG, records(z)));
	}

	// ---------------------------------------------------------------- the primary

	private DnsServer primaryServer(FileSource zoneDir, String... zones) throws IOException {
		for(String z : zones) {
			write(zoneDir.getChild(z+".txt"), zoneText(z, 1));
		}
		java.util.Properties p = new java.util.Properties();
		p.setProperty(DnsServer.PROP_ZONE_DIR, zoneDir.getAbsolutePath());
		p.setProperty(DnsServer.PROP_DEFAULT_ZONE, zones[0]);
		for(String n : p.stringPropertyNames()) {
			System.setProperty(n, p.getProperty(n));
			SET_HERE.add(n);
		}
		DnsServer s = new DnsServer();
		s.setRecursionAvailable(false);
		s.setCatalogZone(CATALOG);
		return s;
	}

	@Test
	public void thePrimaryMakesTheCatalogFromItsZones() throws Exception {
		FileSource dir = folder();
		DnsServer s = primaryServer(dir, "a.test", "b.test");
		s.loadZones();
		Zone cat = s.getZone(CATALOG);
		assertNotNull(cat, "the catalog zone is served");
		assertEquals(set("a.test", "b.test"), CatalogZone.members(CATALOG, records(cat)));
		assertFalse(dir.getChild(CATALOG+".txt").exists(), "the catalog has no zone file");
	}

	@Test
	public void theSerialRisesWhenAZoneIsAddedOrRemovedAndNotOtherwise() throws Exception {
		FileSource dir = folder();
		DnsServer s = primaryServer(dir, "a.test", "b.test");
		s.loadZones();
		int first = s.getZone(CATALOG).getSoa().getSerial();

		s.loadZones();
		assertEquals(first, s.getZone(CATALOG).getSoa().getSerial(), "same zones: same serial");

		//  a restart keeps it too
		DnsServer again = primaryServer(dir, "a.test", "b.test");
		again.loadZones();
		assertEquals(first, again.getZone(CATALOG).getSoa().getSerial(), "same after a restart");

		write(dir.getChild("c.test.txt"), zoneText("c.test", 1));
		s.loadZones();
		int added = s.getZone(CATALOG).getSoa().getSerial();
		assertTrue(SecondaryZones.serialNewer(added, first), "a zone added raises the serial");
		assertEquals(set("a.test", "b.test", "c.test"), CatalogZone.members(CATALOG, records(s.getZone(CATALOG))));

		dir.getChild("c.test.txt").delete();
		s.loadZones();
		int removed = s.getZone(CATALOG).getSoa().getSerial();
		assertTrue(SecondaryZones.serialNewer(removed, added), "a zone removed raises it too");
		assertEquals(set("a.test", "b.test"), CatalogZone.members(CATALOG, records(s.getZone(CATALOG))));
	}

	@Test
	public void theCatalogIsNotChangedByAnUpdate() throws Exception {
		FileSource dir = folder();
		DnsServer s = primaryServer(dir, "a.test");
		s.loadZones();
		s.setUpdateAllow("127.0.0.1");
		Message m = new Message();
		m.setID(9);
		m.getHeader().setOPCODE(DNS.UPDATE);
		m.setQuestion(CATALOG, DNS.SOA, DNS.IN);
		List<Message> r = s.query(new QueryData(InetAddress.getLoopbackAddress(), TCP, m));
		assertEquals(DNS.REFUSED, r.get(0).getResponseCode());
	}

	// ---------------------------------------------------------------- the secondary

	/** A real DnsServer holding the catalog and the member zones, answering transfers over a loopback socket. */
	private final class Primary implements AutoCloseable {
		final DnsServer server = new DnsServer();
		final ServerSocket listener;
		final FileSource zones;
		final AtomicInteger transfers = new AtomicInteger();
		private final List<Socket> sockets = new ArrayList<Socket>();
		private int serial = 1;

		Primary(String... members) throws IOException {
			zones = folder();
			server.setRecursionAvailable(false);
			server.setAxfrAllow("127.0.0.1");
			for(String m : members) {
				addMember(m);
			}
			publish(set(members));
			listener = new ServerSocket(0, 10, InetAddress.getLoopbackAddress());
			Thread acceptor = new Thread(this::accept, "TestCatalogPrimary");
			acceptor.setDaemon(true);
			acceptor.start();
		}

		void addMember(String name) throws IOException {
			FileSource f = zones.getChild(name+".txt");
			write(f, zoneText(name, 1));
			server.addZone(new Zone(f));
		}

		/** Serve a catalog with these members (and a higher serial each time) */
		void publish(Set<String> members) throws IOException {
			publishText(CatalogZone.text(members, serial++));
		}

		void publishText(String text) throws IOException {
			FileSource f = zones.getChild(CATALOG+".txt");
			write(f, text);
			server.addZone(new Zone(f));
		}

		InetSocketAddress address() {
			return new InetSocketAddress(InetAddress.getLoopbackAddress(), listener.getLocalPort());
		}

		private void accept() {
			while( !listener.isClosed() ) {
				try {
					Socket s = listener.accept();
					synchronized(sockets) {
						sockets.add(s);
					}
					Thread t = new Thread(() -> serve(s), "TestCatalogPrimaryConnection");
					t.setDaemon(true);
					t.start();
				} catch(IOException e) {
					return;
				}
			}
		}

		private void serve(Socket s) {
			try(Socket sock = s) {
				sock.setSoTimeout(10000);
				byte [] wire = DnsTransport.readFramed(sock, System.currentTimeMillis()+10000);
				Message m = new Message(new ByteBuffer(wire));
				if( m.getQuestion().get(0).getType() == DNS.AXFR ) {
					transfers.incrementAndGet();
				}
				for(Message a : server.query(new QueryData(sock.getInetAddress(), TCP, m))) {
					sock.getOutputStream().write(DnsTransport.frame(a.toByteArray()));
				}
				sock.getOutputStream().flush();
			} catch(IOException | RuntimeException e) {
				//  the client went away
			}
		}

		@Override
		public void close() throws IOException {
			listener.close();
			synchronized(sockets) {
				for(Socket s : sockets) {
					s.close();
				}
			}
		}
	}

	private final class FakeHost implements SecondaryZones.Host {
		final FileSource zones;
		final AtomicInteger reloads = new AtomicInteger();

		FakeHost() throws IOException {
			zones = folder();
		}

		@Override
		public FileSource getZoneDir() {
			return zones;
		}

		@Override
		public Zone getZone(String zoneName) {
			try {
				FileSource f = zones.getChild(zoneName+".txt");
				return f.exists() ? new Zone(f) : null;
			} catch(IOException e) {
				throw new IllegalStateException(e);
			}
		}

		@Override
		public void reloadZones() {
			reloads.incrementAndGet();
		}
	}

	private SecondaryZones makeSecondary(FakeHost host, Primary p, String zoneNames) {
		SecondaryZones s = new SecondaryZones(host, zoneNames, CATALOG, p.address(), null, us.bringardner.parley.dns.Tsig.DEFAULT_FUDGE, 10000);
		track(s::shutdown);
		return s;
	}

	/** The names of the zones kept, without the catalog's */
	private static Set<String> kept(SecondaryZones s) {
		Set<String> ret = new TreeSet<String>();
		for(SecondaryZones.Entry e : s.getEntries()) {
			if( !e.isCatalog() ) {
				ret.add(e.getName());
			}
		}
		return ret;
	}

	/** Let the background checks run now and wait until every zone kept is served (or fail after 10 seconds) */
	private static void checkAll(SecondaryZones s) throws Exception {
		s.maintain();
		long end = System.currentTimeMillis()+10000;
		while( System.currentTimeMillis() < end ) {
			boolean all = true;
			for(SecondaryZones.Entry e : s.getEntries()) {
				all &= e.getState() == SecondaryZones.State.SERVING;
			}
			if( all ) {
				return;
			}
			Thread.sleep(20);
		}
		for(SecondaryZones.Entry e : s.getEntries()) {
			assertEquals(SecondaryZones.State.SERVING, e.getState(), e.getName()+": "+e.getLastError());
		}
	}

	@Test
	public void aSecondaryKeepsEveryZoneTheCatalogLists() throws Exception {
		Primary p = track(new Primary("a.test", "b.test"));
		FakeHost host = new FakeHost();
		SecondaryZones s = makeSecondary(host, p, null);
		s.start();
		assertEquals(SecondaryZones.State.SERVING, s.get(CATALOG).getState(), String.valueOf(s.get(CATALOG).getLastError()));
		assertEquals(set("a.test", "b.test"), kept(s));
		assertTrue(s.get("a.test").isFromCatalog());
		assertEquals(SecondaryZones.State.PENDING, s.get("a.test").getState(), "not transferred yet");

		checkAll(s);
		assertEquals(SecondaryZones.State.SERVING, s.get("a.test").getState(), String.valueOf(s.get("a.test").getLastError()));
		assertEquals(SecondaryZones.State.SERVING, s.get("b.test").getState());
		assertNotNull(host.getZone("a.test"));
		assertNotNull(host.getZone("b.test"));
		assertNotNull(host.getZone(CATALOG), "the catalog is stored as a zone too");
	}

	@Test
	public void aZoneAddedToTheCatalogIsKeptAtTheNextCheck() throws Exception {
		Primary p = track(new Primary("a.test"));
		FakeHost host = new FakeHost();
		SecondaryZones s = makeSecondary(host, p, null);
		s.start();
		checkAll(s);
		assertEquals(set("a.test"), kept(s));

		p.addMember("b.test");
		p.publish(set("a.test", "b.test"));
		s.check(s.get(CATALOG));
		assertEquals(set("a.test", "b.test"), kept(s));
		checkAll(s);
		assertEquals(SecondaryZones.State.SERVING, s.get("b.test").getState(), String.valueOf(s.get("b.test").getLastError()));
		assertNotNull(host.getZone("b.test"));
	}

	@Test
	public void aZoneTheCatalogDropsIsNoLongerServedAndItsFileIsKept() throws Exception {
		Primary p = track(new Primary("a.test", "b.test"));
		FakeHost host = new FakeHost();
		SecondaryZones s = makeSecondary(host, p, null);
		s.start();
		checkAll(s);
		int reloads = host.reloads.get();

		p.publish(set("a.test"));
		s.check(s.get(CATALOG));
		assertEquals(set("a.test"), kept(s));
		assertNull(s.get("b.test"));
		assertFalse(host.zones.getChild("b.test.txt").exists(), "not loaded at a restart");
		assertTrue(host.zones.getChild("b.test.txt.removed").exists(), "kept to recover");
		assertTrue(host.reloads.get() > reloads, "the zones were loaded again without it");
		assertNotNull(host.getZone("a.test"));
	}

	@Test
	public void aBrokenCatalogChangesNothing() throws Exception {
		Primary p = track(new Primary("a.test", "b.test"));
		FakeHost host = new FakeHost();
		SecondaryZones s = makeSecondary(host, p, null);
		s.start();
		checkAll(s);

		p.publishText(CatalogZone.text(set("a.test"), 50).replace("version\tIN\tTXT\t\"2\"\n", ""));
		s.check(s.get(CATALOG));
		assertEquals(set("a.test", "b.test"), kept(s), "the zones stay as they are");
		assertTrue(host.zones.getChild("b.test.txt").exists());
	}

	@Test
	public void aCatalogWithNoZoneDropsNothing() throws Exception {
		Primary p = track(new Primary("a.test", "b.test"));
		FakeHost host = new FakeHost();
		SecondaryZones s = makeSecondary(host, p, null);
		s.start();
		checkAll(s);

		p.publish(set());
		s.check(s.get(CATALOG));
		assertEquals(set("a.test", "b.test"), kept(s), "an empty catalog is taken for a mistake");
		assertTrue(host.zones.getChild("a.test.txt").exists());
	}

	@Test
	public void theZonesComeBackAfterARestart() throws Exception {
		Primary p = track(new Primary("a.test", "b.test"));
		FakeHost host = new FakeHost();
		SecondaryZones first = makeSecondary(host, p, null);
		first.start();
		checkAll(first);
		first.shutdown();
		int transfers = p.transfers.get();

		SecondaryZones again = makeSecondary(host, p, null);
		again.start();
		assertEquals(SecondaryZones.State.SERVING, again.get(CATALOG).getState(), "served from its file at once");
		assertEquals(set(), kept(again), "which zones came from the catalog is read from it");
		again.check(again.get(CATALOG));
		assertEquals(set("a.test", "b.test"), kept(again), "the files a transfer wrote are ours, not another zone's");
		checkAll(again);
		assertEquals(transfers, p.transfers.get(), "nothing needed to be transferred again");
	}

	@Test
	public void aZoneOfOurOwnIsNotTakenFromTheCatalog() throws Exception {
		Primary p = track(new Primary("a.test", "own.test"));
		FakeHost host = new FakeHost();
		write(host.zones.getChild("own.test.txt"), zoneText("own.test", 9));
		SecondaryZones s = makeSecondary(host, p, null);
		s.start();
		assertEquals(set("a.test"), kept(s));
		assertEquals(9, host.getZone("own.test").getSoa().getSerial(), "our zone file was not touched");
	}

	@Test
	public void aZoneInTheListIsNotDroppedWithTheCatalog() throws Exception {
		Primary p = track(new Primary("a.test", "b.test"));
		FakeHost host = new FakeHost();
		SecondaryZones s = makeSecondary(host, p, "a.test");
		s.start();
		assertFalse(s.get("a.test").isFromCatalog(), "it was in the list");
		checkAll(s);

		p.publish(set("b.test"));
		s.check(s.get(CATALOG));
		assertEquals(set("a.test", "b.test"), kept(s), "a.test is in the list, so it stays");
		assertTrue(host.zones.getChild("a.test.txt").exists());
	}
}
