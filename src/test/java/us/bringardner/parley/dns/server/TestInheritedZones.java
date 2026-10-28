package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.resolve.QueryData;

/**
 * $INHERIT: a domain's zone serves the primary zone's records too, renamed into the domain; the
 * domain's own records add to them or override them (by name and type).
 */
public class TestInheritedZones {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private File dir;
	private DnsServer server;
	private String savedDir;
	private String savedDefault;

	static String primary(int serial, String extra) {
		return "$TTL 300\n@\tIN\tSOA\tns1 postmaster ( "+serial+" 3600 1800 1209600 300 )\n"
				+"\t\tNS\tns1\n"
				+"\t\tMX\t10 mx1\n"
				+"\t\tTXT\t\"v=spf1 mx -all\"\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"mx1\tIN\tA\t10.0.0.25\n"
				+"www\tIN\tA\t10.0.0.80\n"
				+"webmail\tIN\tCNAME\twww\n"
				+"_dmarc\tIN\tTXT\t\"v=DMARC1; p=quarantine\"\n"
				+"*.wild\tIN\tA\t10.0.0.99\n"
				+extra;
	}

	static String child(int serial, String extra) {
		return "$INHERIT primary.test.\n"
				+"$TTL 300\n@\tIN\tSOA\tns1.primary.test. postmaster ( "+serial+" 3600 1800 1209600 300 )\n"
				+"\t\tMX\t20 other.example.\n"
				+"special\tIN\tA\t10.1.0.1\n"
				+"webmail\tIN\tA\t10.1.0.2\n"
				+"www\tIN\tCNAME\tspecial\n"
				+extra;
	}

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("inherit").toFile();
		write("primary.test.txt", primary(10, ""));
		write("child.test.txt", child(5, ""));
		savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "primary.test");
		server = new DnsServer();
		server.loadZones();
		server.setRecursionAvailable(false);
		server.setUpdateAllow("127.0.0.1");
	}

	@AfterEach
	public void cleanup() {
		restore(DnsServer.PROP_ZONE_DIR, savedDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedDefault);
		ZoneNotifier n = server.getNotifier();
		if( n != null ) {
			n.shutdown();
		}
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static void restore(String key, String value) {
		if( value == null ) {
			System.clearProperty(key);
		} else {
			System.setProperty(key, value);
		}
	}

	private void write(String name, String text) throws IOException {
		File f = new File(dir, name);
		long before = f.exists() ? f.lastModified() : 0;
		try(FileWriter w = new FileWriter(f)) {
			w.write(text);
		}
		//  a reload notices the change by its time stamp
		if( f.lastModified() <= before ) {
			f.setLastModified(before+2000);
		}
	}

	private List<String> data(String zone, String name, int type) {
		List<String> ret = new ArrayList<String>();
		for(RR rr : server.getZone(zone).exactRecords(name)) {
			if( rr.getType() == type ) {
				ret.add(Zone.rdataText(rr));
			}
		}
		Collections.sort(ret);
		return ret;
	}

	private Message ask(String name, int type) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		q.setID(0x1234);
		List<Message> r = server.query(new QueryData(LOOPBACK, 5353, q));
		return new Message(new ByteBuffer(r.get(0).toByteArray()));
	}

	private static List<String> answers(Message m) {
		List<String> ret = new ArrayList<String>();
		for(RR rr : m.getAnswer()) {
			ret.add(strip(rr.getName())+" "+us.bringardner.parley.dns.Utility.TYPENAMES[rr.getType()]+" "+Zone.rdataText(rr));
		}
		Collections.sort(ret);
		return ret;
	}

	private static String strip(String n) {
		return n.endsWith(".") ? n.substring(0, n.length()-1) : n;
	}

	private int update(String zone, RR add) {
		Message m = new Message();
		m.setQuestion(zone, DNS.SOA, DNS.IN);
		m.setID(4711);
		m.getHeader().setOPCODE(DNS.UPDATE);
		m.getAuthority().add(add);
		QueryData q = new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(m.toByteArray())));
		Message r = server.query(q).get(0);
		return new Message(new ByteBuffer(r.toByteArray())).getResponseCode();
	}

	private static A a(String name, String ip) {
		A a = new A(name);
		a.setAddress(ip);
		a.setTTL(300);
		return a;
	}

	@Test
	public void inheritsWhatItDoesNotHave() {
		Zone z = server.getZone("child.test");
		assertTrue(z.isInherited());
		assertEquals("primary.test", z.getOwn().getInheritFrom());
		// the primary's records, under the child's names, with their data as written
		assertEquals("[ns1.primary.test.]", data("child.test", "child.test", DNS.NS).toString());
		assertEquals("[\"v=spf1 mx -all\"]", data("child.test", "child.test", DNS.TXT).toString());
		assertEquals("[\"v=DMARC1; p=quarantine\"]", data("child.test", "_dmarc.child.test", DNS.TXT).toString());
		assertEquals("[10.0.0.25]", data("child.test", "mx1.child.test", DNS.A).toString());
		assertEquals("[10.0.0.99]", data("child.test", "*.wild.child.test", DNS.A).toString());
		// the primary itself is untouched
		assertFalse(server.getZone("primary.test").isInherited());
		assertEquals("[10 mx1.primary.test.]", data("primary.test", "primary.test", DNS.MX).toString());
	}

	@Test
	public void ownRecordsOverrideByNameAndType() {
		// own MX replaces the inherited one
		assertEquals("[20 other.example.]", data("child.test", "child.test", DNS.MX).toString());
		// own A at webmail: the inherited CNAME can't share the name
		assertEquals("[10.1.0.2]", data("child.test", "webmail.child.test", DNS.A).toString());
		assertTrue(data("child.test", "webmail.child.test", DNS.CNAME).isEmpty());
		// own CNAME at www hides the inherited A
		assertEquals("[special.child.test.]", data("child.test", "www.child.test", DNS.CNAME).toString());
		assertTrue(data("child.test", "www.child.test", DNS.A).isEmpty());
		// own only
		assertEquals("[10.1.0.1]", data("child.test", "special.child.test", DNS.A).toString());
	}

	@Test
	public void soaIsOwnWithBothSerials() {
		Zone z = server.getZone("child.test");
		assertEquals("child.test", strip(z.getSoa().getName()));
		assertEquals(15, z.getSoa().getSerial());
		assertEquals(5, z.getOwn().getSoa().getSerial());
	}

	@Test
	public void answersQueries() {
		Message m = ask("mx1.child.test", DNS.A);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertTrue(m.getHeader().getAA());
		assertEquals("[mx1.child.test A 10.0.0.25]", answers(m).toString());
		m = ask("child.test", DNS.MX);
		assertEquals("[child.test MX 20 other.example.]", answers(m).toString());
		m = ask("x.wild.child.test", DNS.A);
		assertEquals("[x.wild.child.test A 10.0.0.99]", answers(m).toString());
		assertEquals(DNS.NAME_ERROR, ask("nothing.child.test", DNS.A).getResponseCode());
	}

	@Test
	public void updateChangesOwnRecordsAndIsJournaledAgainstOwnSerial() throws Exception {
		// an own A at mx1 overrides the inherited one
		assertEquals(DNS.NOERROR, update("child.test", a("mx1.child.test", "10.1.0.25")));
		assertEquals("[10.1.0.25]", data("child.test", "mx1.child.test", DNS.A).toString());
		Zone z = server.getZone("child.test");
		assertTrue(z.isInherited());
		assertEquals(6, z.getOwn().getSoa().getSerial());
		assertEquals(16, z.getSoa().getSerial());
		String jnl = new String(Files.readAllBytes(new File(dir, "child.test.txt.jnl").toPath()), StandardCharsets.UTF_8);
		assertTrue(jnl.contains("base 5\n"), jnl);
		assertFalse(jnl.contains("10.0.0."), "only the own change is journaled: "+jnl);

		// survives a restart: the journal is replayed on the own records, then the primary's added
		DnsServer again = new DnsServer();
		again.loadZones();
		Zone z2 = again.getZone("child.test");
		assertEquals(16, z2.getSoa().getSerial());
		assertEquals(1, z2.exactRecords("mx1.child.test").size());
		assertEquals("10.1.0.25", Zone.rdataText(z2.exactRecords("mx1.child.test").get(0)));
	}

	@Test
	public void primaryUpdateReachesTheChild() {
		assertEquals(DNS.NOERROR, update("primary.test", a("new.primary.test", "10.0.0.7")));
		assertEquals("[10.0.0.7]", data("child.test", "new.child.test", DNS.A).toString());
		assertEquals(11, server.getZone("primary.test").getSoa().getSerial());
		assertEquals(16, server.getZone("child.test").getSoa().getSerial());
	}

	@Test
	public void reloadPicksUpPrimaryChanges() throws Exception {
		Zone before = server.getZone("child.test");
		write("primary.test.txt", primary(11, "ftp\tIN\tA\t10.0.0.21\n"));
		server.loadZones();
		Zone after = server.getZone("child.test");
		assertEquals("[10.0.0.21]", data("child.test", "ftp.child.test", DNS.A).toString());
		assertEquals(16, after.getSoa().getSerial());
		// the child's file didn't change: its own records were reused
		assertSame(before.getOwn(), after.getOwn());
	}

	@Test
	public void withoutItsPrimaryOnlyOwnRecordsAreServed() throws Exception {
		write("lone.test.txt", "$INHERIT nowhere.test\n$TTL 300\n@\tIN\tSOA\tns1 postmaster ( 1 3600 1800 1209600 300 )\n"
				+"a\tIN\tA\t10.2.0.1\n");
		write("chain.test.txt", "$INHERIT child.test\n$TTL 300\n@\tIN\tSOA\tns1 postmaster ( 1 3600 1800 1209600 300 )\n");
		server.loadZones();
		Zone lone = server.getZone("lone.test");
		assertNotNull(lone);
		assertFalse(lone.isInherited());
		assertEquals("[10.2.0.1]", data("lone.test", "a.lone.test", DNS.A).toString());
		// one level only: a zone can't inherit from a zone that inherits
		assertFalse(server.getZone("chain.test").isInherited());
	}

	@Test
	public void anInheritedDelegationDoesNotHideOwnRecords() throws Exception {
		write("primary.test.txt", primary(11, "lab\tIN\tNS\tns.elsewhere.example.\nsub\tIN\tNS\tns.elsewhere.example.\n"));
		write("child.test.txt", child(6, "lab\tIN\tA\t10.1.0.9\nhost.lab\tIN\tA\t10.1.0.10\n"));
		server.loadZones();
		assertTrue(data("child.test", "lab.child.test", DNS.NS).isEmpty(), "not inherited over own records");
		Message m = ask("host.lab.child.test", DNS.A);
		assertTrue(m.getHeader().getAA());
		assertEquals("[host.lab.child.test A 10.1.0.10]", answers(m).toString());
		assertEquals("[lab.child.test A 10.1.0.9]", answers(ask("lab.child.test", DNS.A)).toString());
		// where the zone has nothing of its own, the delegation is inherited
		assertEquals("[ns.elsewhere.example.]", data("child.test", "sub.child.test", DNS.NS).toString());
	}

	@Test
	public void withoutItsPrimaryTheLastVersionIsKept() throws Exception {
		assertEquals(15, server.getZone("child.test").getSoa().getSerial());
		new File(dir, "primary.test.txt").delete();
		write("other.test.txt", "@ IN SOA ns1 postmaster ( 1 3600 1800 1209600 300 )\n");
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "other.test");
		server.loadZones();
		Zone z = server.getZone("child.test");
		assertEquals(15, z.getSoa().getSerial(), "its serial doesn't go down");
		assertEquals("[10.0.0.25]", data("child.test", "mx1.child.test", DNS.A).toString());
	}

	@Test
	public void serialArithmetic() {
		assertTrue(DnsServer.serialBefore(5, 15));
		assertFalse(DnsServer.serialBefore(15, 5));
		assertFalse(DnsServer.serialBefore(5, 5));
		assertTrue(DnsServer.serialBefore(0xfffffff0, 3), "wraps (RFC 1982)");
	}

	@Test
	public void directiveRules() throws Exception {
		String soa = "@\tIN\tSOA\tns1 postmaster ( 1 3600 1800 1209600 300 )\n";
		assertThrows(IOException.class, () -> zone("twice.test", "$INHERIT a.test\n$INHERIT b.test\n"+soa));
		assertThrows(IOException.class, () -> zone("self.test", "$INHERIT self.test.\n"+soa));
		assertThrows(IOException.class, () -> zone("none.test", "$INHERIT\n"+soa));
		File inc = new File(dir, "inherit.inc");
		try(FileWriter w = new FileWriter(inc)) {
			w.write("$INHERIT primary.test\n");
		}
		assertThrows(IOException.class, () -> zone("inc.test", soa+"$INCLUDE inherit.inc\n"));
		assertEquals("primary.test", zone("ok.test", "$INHERIT Primary.Test.\n"+soa).getInheritFrom());
	}

	private Zone zone(String name, String text) throws IOException {
		File f = new File(dir, name+".zone");
		try(FileWriter w = new FileWriter(f)) {
			w.write(text);
		}
		try {
			return new Zone(f);
		} finally {
			f.delete();
		}
	}
}
