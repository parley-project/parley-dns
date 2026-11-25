package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.DnsTransport;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.TestFiles;
import us.bringardner.parley.dns.Tsig;
import us.bringardner.parley.dns.resolve.QueryData;
import us.bringardner.parley.files.FileSource;

/**
 * A server as a secondary: transferring a zone from a primary (TSIG signed or not), what is stored,
 * refresh, retry and expire, and what the server does with NOTIFY, queries and updates for a secondary zone.
 * The primary is a real DnsServer answering over a loopback socket, so the transfers are its real AXFR.
 */
public class TestSecondaryZones {

	/** The system properties a test set with setSystem, cleared after it */
	private static final java.util.Set<String> SET_HERE = new java.util.HashSet<>();

	private static void setSystem(java.util.Properties settings) {
		for (String n : settings.stringPropertyNames()) {
			System.setProperty(n, settings.getProperty(n));
			SET_HERE.add(n);
		}
	}

	@org.junit.jupiter.api.AfterEach
	public void clearSystem() {
		for (String n : SET_HERE) {
			System.clearProperty(n);
		}
		SET_HERE.clear();
	}


	@TempDir
	static Path tmp;

	private static final String ZONE = "sec.test";
	private static final String KEY_SPEC = "xfr.key:hmac-sha256:aGVsbG8gd29ybGQgMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=";
	private static final String OTHER_KEY_SPEC = "other.key:hmac-sha256:b3RoZXIgc2VjcmV0IG90aGVyIHNlY3JldCBvdGhlcjEyMw==";
	private static final int TCP = -1;

	private final List<AutoCloseable> open = new ArrayList<AutoCloseable>();
	private FileSource dir;
	private int folders;

	private static String zoneText(int serial, String extra) {
		return "$TTL 300\n@\tIN\tSOA\tns1 postmaster ( "+serial+" 3600 1800 1209600 300 )\n"
				+"\t\tNS\tns1\n"
				+"\t\tMX\t10 mail\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"mail\tIN\tA\t10.0.0.25\n"
				+"www\tIN\tA\t10.0.0.80\n"
				+"txt\tIN\tTXT\t\"v=spf1 mx -all\" \"second string\"\n"
				+extra;
	}

	private FileSource folder() throws IOException {
		return TestFiles.newFolder(tmp, "secondary"+(folders++));
	}

	private static void write(FileSource f, String text) throws IOException {
		try(Writer w = TestFiles.writer(f)) {
			w.write(text);
		}
	}

	private <T extends AutoCloseable> T track(T c) {
		open.add(c);
		return c;
	}

	@BeforeEach
	public void setup() throws IOException {
		dir = folder();
	}

	@AfterEach
	public void cleanup() throws Exception {
		for(int i=open.size()-1; i >= 0; i--) {
			open.get(i).close();
		}
		open.clear();
	}

	/** A DnsServer serving a zone and answering zone transfers over a loopback socket, signed when it has keys. */
	private final class Primary implements AutoCloseable {
		final DnsServer server = new DnsServer();
		final ServerSocket listener;
		final Thread acceptor;
		final FileSource file;
		final Tsig.KeyRing keys;
		final AtomicInteger transfers = new AtomicInteger();
		final AtomicInteger soaQueries = new AtomicInteger();
		volatile boolean refuse;
		volatile String extraName;		//  a record outside the zone to put in the transfer
		private final List<Socket> sockets = new ArrayList<Socket>();

		Primary(int serial, String keySpec) throws IOException {
			file = folder().getChild(ZONE+".txt");
			write(file, zoneText(serial, ""));
			server.addZone(new Zone(file));
			server.setRecursionAvailable(false);
			keys = Tsig.KeyRing.parse(keySpec);
			server.setTsigKeys(keys);
			if( keySpec == null ) {
				server.setAxfrAllow("127.0.0.1");
			} else {
				server.setAxfrKeys("xfr.key");
			}
			listener = new ServerSocket(0, 10, InetAddress.getLoopbackAddress());
			acceptor = new Thread(this::accept, "TestPrimary");
			acceptor.setDaemon(true);
			acceptor.start();
		}

		void setSerial(int serial) throws IOException {
			write(file, zoneText(serial, ""));
			server.addZone(new Zone(file));
		}

		int port() {
			return listener.getLocalPort();
		}

		InetSocketAddress address() {
			return new InetSocketAddress(InetAddress.getLoopbackAddress(), port());
		}

		private void accept() {
			while( !listener.isClosed() ) {
				try {
					Socket s = listener.accept();
					synchronized(sockets) {
						sockets.add(s);
					}
					Thread t = new Thread(() -> serve(s), "TestPrimaryConnection");
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
				Tsig.Session tsig = Tsig.Session.verifyRequest(keys, wire);
				QueryData q = new QueryData(sock.getInetAddress(), TCP, m);
				if( tsig != null ) {
					q.setTsigKey(tsig.getKey() == null ? null : tsig.getKey().getName());
				}
				if( m.getQuestion().get(0).getType() == DNS.AXFR ) {
					transfers.incrementAndGet();
				} else {
					soaQueries.incrementAndGet();
				}
				List<Message> answers = refuse ? refused(m) : server.query(q);
				for(Message a : answers) {
					if( extraName != null && a.getAnswerCount() > 0 && m.getQuestion().get(0).getType() == DNS.AXFR ) {
						us.bringardner.parley.dns.A extra = new us.bringardner.parley.dns.A(extraName);
						extra.setAddress("10.9.9.9");
						extra.setTTL(300);
						a.getAnswer().add(a.getAnswer().size()-1, extra);
					}
					byte [] out = a.toByteArray();
					if( tsig != null ) {
						out = tsig.signResponse(out);
					}
					sock.getOutputStream().write(DnsTransport.frame(out));
				}
				sock.getOutputStream().flush();
			} catch(IOException | RuntimeException e) {
				//  the client went away
			}
		}

		private List<Message> refused(Message m) {
			Message r = new Message();
			r.setHeader(m.getHeader().copy());
			r.setMessageTypeResponse();
			r.setQuestion(m.getQuestion().get(0));
			r.setResponseCodeRefused();
			List<Message> ret = new ArrayList<Message>();
			ret.add(r);
			return ret;
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

	/** A secondary's host: its zone folder, and the zones read back from it. */
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

	private SecondaryZones secondary(FakeHost host, Primary p, String keyName) {
		Tsig.Key key = keyName == null ? null : p.keys.get(keyName);
		return new SecondaryZones(host, ZONE, p.address(), key, Tsig.DEFAULT_FUDGE, 10000);
	}

	@Test
	public void firstStartTransfersAndStoresTheZone() throws Exception {
		Primary p = track(new Primary(5, null));
		FakeHost host = new FakeHost();
		SecondaryZones s = secondary(host, p, null);
		assertEquals(SecondaryZones.State.PENDING, s.get(ZONE).getState());
		assertTrue(s.isUnavailable("www."+ZONE), "not served before the first transfer");
		s.start();
		assertEquals(SecondaryZones.State.SERVING, s.get(ZONE).getState());
		assertFalse(s.isUnavailable("www."+ZONE));
		Zone z = host.getZone(ZONE);
		assertNotNull(z, "the zone was stored");
		assertEquals(5, z.getSoa().getSerial());
		List<RR> mine = z.getRrs().stream().flatMap(List::stream).collect(java.util.stream.Collectors.toList());
		List<RR> theirs = p.server.getZone(ZONE).getRrs().stream().flatMap(List::stream).collect(java.util.stream.Collectors.toList());
		assertEquals(theirs.size(), mine.size(), "every record came across");
		//  a TXT with two strings and the TTLs come across intact
		Zone.recordLine(mine.get(0));
		for(RR t : theirs) {
			boolean found = false;
			for(RR m : mine) {
				found |= Zone.recordLine(m).equals(Zone.recordLine(t));
			}
			assertTrue(found, "record not stored as sent: "+Zone.recordLine(t));
		}
		assertFalse(zonesFolderHasTemporaryFile(host), "the temporary file is gone");
		s.shutdown();
	}

	private static boolean zonesFolderHasTemporaryFile(FakeHost host) throws IOException {
		for(FileSource f : host.zones.listFiles()) {
			if( f.getName().endsWith(".transfer") ) {
				return true;
			}
		}
		return false;
	}

	@Test
	public void aSignedTransferNeedsTheKey() throws Exception {
		Primary p = track(new Primary(5, KEY_SPEC));
		FakeHost host = new FakeHost();
		SecondaryZones s = secondary(host, p, "xfr.key");
		s.start();
		assertEquals(SecondaryZones.State.SERVING, s.get(ZONE).getState(), String.valueOf(s.get(ZONE).getLastError()));
		assertEquals(5, host.getZone(ZONE).getSoa().getSerial());
		s.shutdown();

		//  no key: the primary refuses (it allows signed requests only)
		FakeHost h2 = new FakeHost();
		SecondaryZones unsigned = secondary(h2, p, null);
		unsigned.start();
		assertEquals(SecondaryZones.State.PENDING, unsigned.get(ZONE).getState());
		assertNull(h2.getZone(ZONE));
		assertNotNull(unsigned.get(ZONE).getLastError());
		unsigned.shutdown();

		//  a key the primary doesn't know: nothing is stored either
		Tsig.Key wrong = Tsig.KeyRing.parse(OTHER_KEY_SPEC).get("other.key");
		FakeHost h3 = new FakeHost();
		SecondaryZones bad = new SecondaryZones(h3, ZONE, p.address(), wrong, Tsig.DEFAULT_FUDGE, 10000);
		bad.start();
		assertEquals(SecondaryZones.State.PENDING, bad.get(ZONE).getState());
		assertNull(h3.getZone(ZONE));
		bad.shutdown();
	}

	@Test
	public void aTransferWithANameOutsideTheZoneIsThrownAway() throws Exception {
		Primary p = track(new Primary(5, null));
		p.extraName = "evil.example.com";
		FakeHost host = new FakeHost();
		SecondaryZones s = secondary(host, p, null);
		s.start();
		assertEquals(SecondaryZones.State.PENDING, s.get(ZONE).getState());
		assertNull(host.getZone(ZONE), "nothing was stored");
		assertTrue(s.get(ZONE).getLastError().contains("not in the zone"), s.get(ZONE).getLastError());
		s.shutdown();
	}

	@Test
	public void aCheckTransfersOnlyWhenThePrimaryHasANewerSerial() throws Exception {
		Primary p = track(new Primary(5, null));
		FakeHost host = new FakeHost();
		SecondaryZones s = secondary(host, p, null);
		s.start();
		assertEquals(1, p.transfers.get());

		s.check(s.get(ZONE));
		assertEquals(1, p.transfers.get(), "same serial: no transfer");
		assertEquals(0, host.reloads.get());
		assertEquals(SecondaryZones.State.SERVING, s.get(ZONE).getState());

		p.setSerial(6);
		s.check(s.get(ZONE));
		assertEquals(2, p.transfers.get());
		assertEquals(1, host.reloads.get(), "the new zone is loaded");
		assertEquals(6, host.getZone(ZONE).getSoa().getSerial());
		s.shutdown();
	}

	@Test
	public void aFailedCheckKeepsTheZoneWeHave() throws Exception {
		Primary p = track(new Primary(5, null));
		FakeHost host = new FakeHost();
		SecondaryZones s = secondary(host, p, null);
		s.start();
		p.setSerial(6);
		p.refuse = true;
		assertThrows(IOException.class, () -> s.check(s.get(ZONE)));
		assertEquals(5, host.getZone(ZONE).getSoa().getSerial(), "the zone we have is still there");
		assertEquals(SecondaryZones.State.SERVING, s.get(ZONE).getState());
		s.shutdown();
	}

	@Test
	public void aZoneExpiresWhenThePrimaryCannotBeReached() throws Exception {
		Primary p = track(new Primary(5, null));
		FakeHost host = new FakeHost();
		//  a stored zone that expires in one second
		write(host.zones.getChild(ZONE+".txt"), "$TTL 300\n"+ZONE+". 300 IN SOA ns1."+ZONE+". postmaster."+ZONE+". 4 1 1 1 300\n"
				+ZONE+". 300 IN NS ns1."+ZONE+".\nns1."+ZONE+". 300 IN A 10.0.0.53\n");
		p.close();		//  nobody answers
		SecondaryZones s = secondary(host, p, null);
		s.start();
		assertEquals(SecondaryZones.State.SERVING, s.get(ZONE).getState(), "served at once from the file");
		Thread.sleep(1300);
		s.maintain();
		assertEquals(SecondaryZones.State.EXPIRED, s.get(ZONE).getState());
		assertTrue(s.isUnavailable("ns1."+ZONE));
		s.shutdown();
	}

	@Test
	public void serialNumbersAreComparedAsInRfc1982() {
		assertTrue(SecondaryZones.serialNewer(2, 1));
		assertFalse(SecondaryZones.serialNewer(1, 2));
		assertFalse(SecondaryZones.serialNewer(7, 7));
		assertTrue(SecondaryZones.serialNewer(1, 0xFFFFFFFF), "a serial that wrapped is newer");
		assertFalse(SecondaryZones.serialNewer(0xFFFFFFFF, 1));
	}

	@Test
	public void namesBelongToTheNearestSecondaryZone() throws Exception {
		Primary p = track(new Primary(5, null));
		SecondaryZones s = secondary(new FakeHost(), p, null);
		assertEquals(ZONE, s.find("a.b."+ZONE+".").getName());
		assertEquals(ZONE, s.find(ZONE).getName());
		assertNull(s.find("other.test"));
		assertNull(s.find("notsec.test"), "a name only ending the same way is not inside the zone");
		s.shutdown();
	}

	// ---------------------------------------------------------------- the server

	private DnsServer serverFor(Primary p, String keyName, FileSource zoneDir) {
		Properties config = new Properties();
		config.setProperty(DnsServer.PROP_ZONE_DIR, zoneDir.getAbsolutePath());
		config.setProperty(DnsServer.PROP_DEFAULT_ZONE, ZONE);
		setSystem(config);
		DnsServer server = new DnsServer();
		server.setRecursionAvailable(false);
		server.setTsigKeys(Tsig.KeyRing.parse(KEY_SPEC));
		server.setSecondaryZones(ZONE, "127.0.0.1:"+p.port(), keyName, 10000);
		track(() -> server.getSecondaries().shutdown());
		return server;
	}

	private static Message query(DnsServer server, int opcode, String name, int type, InetAddress from, String tsigKey) {
		Message m = new Message();
		m.setID(7);
		m.getHeader().setOPCODE(opcode);
		m.setQuestion(name, type, DNS.IN);
		QueryData q = new QueryData(from, TCP, m);
		q.setTsigKey(tsigKey);
		List<Message> r = server.query(q);
		assertEquals(1, r.size());
		return r.get(0);
	}

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

	private static InetAddress other() throws IOException {
		return InetAddress.getByName("192.0.2.77");
	}

	@Test
	public void aSecondaryZoneNotTransferredYetAnswersServfail() throws Exception {
		Primary p = track(new Primary(5, null));
		DnsServer server = serverFor(p, null, dir);
		Message r = query(server, DNS.QUERY, "www."+ZONE, DNS.A, LOOPBACK, null);
		assertEquals(DNS.SERVER_ERROR, r.getResponseCode());
	}

	@Test
	public void notifyFromThePrimaryChecksTheZone() throws Exception {
		Primary p = track(new Primary(5, null));
		DnsServer server = serverFor(p, null, dir);
		Message r = query(server, DNS.NOTIFY, ZONE, DNS.SOA, LOOPBACK, null);
		assertEquals(DNS.NOERROR, r.getResponseCode());
		long end = System.currentTimeMillis()+10000;
		while( server.getSecondaries().get(ZONE).getState() != SecondaryZones.State.SERVING && System.currentTimeMillis() < end ) {
			Thread.sleep(50);
		}
		assertEquals(SecondaryZones.State.SERVING, server.getSecondaries().get(ZONE).getState(),
				String.valueOf(server.getSecondaries().get(ZONE).getLastError()));
		assertTrue(dir.getChild(ZONE+".txt").exists(), "the zone was stored by the transfer the NOTIFY started");
		Message a = query(server, DNS.QUERY, "www."+ZONE, DNS.A, LOOPBACK, null);
		assertEquals(DNS.NOERROR, a.getResponseCode());
		assertEquals(1, a.getAnswerCount());
	}

	@Test
	public void notifyFromAnyoneElseIsRefused() throws Exception {
		Primary p = track(new Primary(5, null));
		DnsServer server = serverFor(p, null, dir);
		assertEquals(DNS.REFUSED, query(server, DNS.NOTIFY, ZONE, DNS.SOA, other(), null).getResponseCode());
		assertEquals(0, p.soaQueries.get()+p.transfers.get(), "nothing was asked of the primary");
	}

	@Test
	public void notifyNeedsTheKeyWhenOneIsSet() throws Exception {
		Primary p = track(new Primary(5, KEY_SPEC));
		DnsServer server = serverFor(p, "xfr.key", dir);
		assertEquals(DNS.REFUSED, query(server, DNS.NOTIFY, ZONE, DNS.SOA, LOOPBACK, null).getResponseCode(), "unsigned");
		assertEquals(DNS.REFUSED, query(server, DNS.NOTIFY, ZONE, DNS.SOA, LOOPBACK, "other.key").getResponseCode(), "another key");
		assertEquals(DNS.NOERROR, query(server, DNS.NOTIFY, ZONE, DNS.SOA, LOOPBACK, "xfr.key").getResponseCode(), "the primary's key");
	}

	@Test
	public void notifyForAZoneWeDoNotKeepIsNotAuth() throws Exception {
		Primary p = track(new Primary(5, null));
		DnsServer server = serverFor(p, null, dir);
		assertEquals(ZoneUpdater.NOTAUTH, query(server, DNS.NOTIFY, "other.test", DNS.SOA, LOOPBACK, null).getResponseCode());
	}

	@Test
	public void anUpdateOfASecondaryZoneIsRefused() throws Exception {
		Primary p = track(new Primary(5, null));
		DnsServer server = serverFor(p, null, dir);
		Message m = new Message();
		m.setID(9);
		m.getHeader().setOPCODE(DNS.UPDATE);
		m.setQuestion(ZONE, DNS.SOA, DNS.IN);
		server.setUpdateAllow("127.0.0.1");
		List<Message> r = server.query(new QueryData(LOOPBACK, TCP, m));
		assertEquals(DNS.REFUSED, r.get(0).getResponseCode());
	}

	@Test
	public void aServerWithoutSecondaryZonesStillAnswersNotifyNotImplemented() throws Exception {
		DnsServer server = new DnsServer();
		Message r = query(server, DNS.NOTIFY, ZONE, DNS.SOA, LOOPBACK, null);
		assertEquals(DNS.NOT_IMPLEMENTED, r.getResponseCode());
	}
}
