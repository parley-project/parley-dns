package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
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
import us.bringardner.parley.dns.Txt;
import us.bringardner.parley.dns.resolve.QueryData;

/**
 * parley.dns.domainList: the listed domains (here the mail queue's queue.properties domains=) are
 * served from the shared zone (parley.dns.sharedZone) with no zone file, each under its own name;
 * the shared zone's DKIM record (the shared key) with them; and their DMARC report authorizations
 * from the master zone.
 */
public class TestListedDomains {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static final int REFUSED = 5;
	private static final int NXDOMAIN = 3;
	private File dir;
	private File keys;
	private File settings;
	private DnsServer server;
	private String savedDir;
	private String savedDefault;
	private String savedList;
	private String savedShared;

	static final String DKIM = "mx1._domainkey\tIN\tTXT\t\"v=DKIM1; k=rsa; p=SHARED\"\n";

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("listed").toFile();
		keys = Files.createTempDirectory("listedsettings").toFile();
		write(new File(dir, "primary.test.txt"), TestInheritedZones.primary(10, DKIM));
		write(new File(dir, "child.test.txt"), TestInheritedZones.child(5, ""));
		write(new File(dir, "shared.zone"), TestInheritedZones.primary(10, DKIM));
		settings = new File(keys, "queue.properties");
		settings("primary.test,child.test,Mail.Example.");
		savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		savedList = System.getProperty(DnsServer.PROP_DOMAIN_LIST+".file");
		savedShared = System.getProperty(DnsServer.PROP_SHARED_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "primary.test");
		System.setProperty(DnsServer.PROP_DOMAIN_LIST+".file", settings.getAbsolutePath());
		System.setProperty(DnsServer.PROP_SHARED_ZONE, new File(dir, "shared.zone").getAbsolutePath());
		server = new DnsServer();
		server.loadZones();
		server.setRecursionAvailable(false);
		server.setUpdateAllow("127.0.0.1");
	}

	private void settings(String domains) throws IOException {
		write(settings, "hostname=mx1.primary.test\ndomains="+domains+"\ndkim.shared=primary.test\n");
	}

	@AfterEach
	public void cleanup() {
		restore(DnsServer.PROP_ZONE_DIR, savedDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedDefault);
		restore(DnsServer.PROP_DOMAIN_LIST+".file", savedList);
		restore(DnsServer.PROP_SHARED_ZONE, savedShared);
		ZoneNotifier n = server.getNotifier();
		if( n != null ) {
			n.shutdown();
		}
		for(File d : new File[] {dir, keys}) {
			for(File f : d.listFiles()) {
				f.delete();
			}
			d.delete();
		}
	}

	private static void restore(String key, String value) {
		if( value == null ) {
			System.clearProperty(key);
		} else {
			System.setProperty(key, value);
		}
	}

	private static void write(File f, String text) throws IOException {
		long before = f.exists() ? f.lastModified() : 0;
		try(FileWriter w = new FileWriter(f)) {
			w.write(text);
		}
		//  a reload notices the change by its time stamp
		if( f.lastModified() <= before ) {
			f.setLastModified(before+2000);
		}
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

	private static String txt(Message m) {
		assertEquals(1, m.getAnswerCount(), answers(m).toString());
		return ((Txt) m.getAnswer().get(0)).getText();
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

	@Test
	public void aListedDomainIsServedFromTheSharedZoneWithNoFile() {
		Zone z = server.getZone("mail.example");
		assertNotNull(z, "served");
		assertTrue(z.getOwn().isVirtual());
		assertEquals(Zone.SHARED, z.getOwn().getInheritFrom());
		assertFalse(new File(dir, "mail.example.txt").exists(), "no zone file");

		Message m = ask("mail.example", DNS.MX);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertTrue(m.isAuthority());
		// relative names in the shared zone's data are the domain's
		assertEquals("[mail.example MX 10 mx1.mail.example.]", answers(m).toString());
		assertEquals("[mx1.mail.example A 10.0.0.25]", answers(ask("mx1.mail.example", DNS.A)).toString());
		// its wildcard, under the domain
		assertEquals("[x.wild.mail.example A 10.0.0.99]", answers(ask("x.wild.mail.example", DNS.A)).toString());
		assertEquals(NXDOMAIN, ask("nothing.mail.example", DNS.A).getResponseCode());
		assertEquals("\"v=spf1 mx -all\"", answers(ask("mail.example", DNS.TXT)).get(0).replace("mail.example TXT ", ""));
		assertEquals("[_dmarc.mail.example TXT \"v=DMARC1; p=quarantine\"]", answers(ask("_dmarc.mail.example", DNS.TXT)).toString());
		Message soa = ask("mail.example", DNS.SOA);
		assertEquals(1, soa.getAnswerCount());
		assertEquals("mail.example", strip(soa.getAnswer().get(0).getName()));
		assertEquals("ns1.mail.example", strip(((us.bringardner.parley.dns.Soa)soa.getAnswer().get(0)).getMname()));
		// a negative answer carries the domain's SOA, not the master's
		Message neg = ask("nothing.mail.example", DNS.A);
		assertEquals("mail.example", strip(neg.getAuthority().get(0).getName()));

		// a domain with a zone of its own keeps it; one that isn't listed isn't served
		assertFalse(server.getZone("child.test").getOwn().isVirtual());
		assertEquals(REFUSED, ask("other.example", DNS.MX).getResponseCode());

		// on the admin's DNS page: a zone with no file
		DnsServerManagement mgmt = new DnsServerManagement(server);
		boolean found = false;
		for(DnsZoneInfo i : mgmt.getZones()) {
			if( i.getName().equals("mail.example") ) {
				found = true;
				assertEquals(Zone.SHARED, i.getInheritFrom());
				assertNull(i.getFile());
			}
		}
		assertTrue(found);
	}

	@Test
	public void theSharedZonesDkimRecordIsServedForEveryDomain() throws Exception {
		assertEquals("v=DKIM1; k=rsa; p=SHARED", txt(ask("mx1._domainkey.primary.test", DNS.TXT)));
		assertEquals("v=DKIM1; k=rsa; p=SHARED", txt(ask("mx1._domainkey.mail.example", DNS.TXT)));
		assertEquals("v=DKIM1; k=rsa; p=SHARED", txt(ask("mx1._domainkey.child.test", DNS.TXT)));
		// another change to the settings file, with the same domains, reloads nothing
		write(settings, "hostname=mx2.primary.test\ndomains=primary.test,child.test,Mail.Example.\n");
		assertFalse(server.shouldReloadZones());
	}

	@Test
	public void dmarcReportsAreAuthorized() {
		assertEquals("v=DMARC1", txt(ask("mail.example._report._dmarc.primary.test", DNS.TXT)));
		assertEquals("v=DMARC1", txt(ask("child.test._report._dmarc.primary.test", DNS.TXT)));
		// only for the listed domains
		assertEquals(NXDOMAIN, ask("other.example._report._dmarc.primary.test", DNS.TXT).getResponseCode());
		Message above = ask("_report._dmarc.primary.test", DNS.TXT);
		assertEquals(DNS.NOERROR, above.getResponseCode());
		assertEquals(0, above.getAnswerCount());
		// the master zone's own DMARC record is untouched
		assertEquals("[_dmarc.primary.test TXT \"v=DMARC1; p=quarantine\"]", answers(ask("_dmarc.primary.test", DNS.TXT)).toString());
	}

	@Test
	public void aDomainRemovedFromTheListIsNoLongerServed() throws Exception {
		settings("primary.test,child.test");
		assertTrue(server.shouldReloadZones());
		server.loadZones();
		assertNull(server.getZone("mail.example"));
		assertEquals(REFUSED, ask("mail.example", DNS.MX).getResponseCode());
		assertEquals(NXDOMAIN, ask("mail.example._report._dmarc.primary.test", DNS.TXT).getResponseCode());
		// a domain with a zone file is served from it, listed or not
		assertNotNull(server.getZone("child.test"));
	}

	@Test
	public void aChangeWritesTheZoneFile() throws Exception {
		A a = new A("special.mail.example");
		a.setAddress("10.2.0.1");
		a.setTTL(300);
		assertEquals(DNS.NOERROR, update("mail.example", a));
		File file = new File(dir, "mail.example.txt");
		assertTrue(file.exists(), "the zone file is written");
		assertTrue(new File(dir, "mail.example.txt.jnl").exists(), "and the change journaled beside it");
		assertEquals("[special.mail.example A 10.2.0.1]", answers(ask("special.mail.example", DNS.A)).toString());
		assertEquals("[mail.example MX 10 mx1.mail.example.]", answers(ask("mail.example", DNS.MX)).toString());
		assertTrue(new String(Files.readAllBytes(file.toPath()), java.nio.charset.StandardCharsets.UTF_8).contains("$INHERIT\n"));

		// read back from the file: the same zone, now with a file
		assertTrue(server.shouldReloadZones());
		server.loadZones();
		Zone z = server.getZone("mail.example");
		assertFalse(z.getOwn().isVirtual());
		assertEquals(Zone.SHARED, z.getOwn().getInheritFrom());
		assertEquals("[special.mail.example A 10.2.0.1]", answers(ask("special.mail.example", DNS.A)).toString());

		// with a file it stays served when it leaves the list (its own records added to the shared zone's)
		settings("primary.test,child.test");
		server.loadZones();
		assertEquals("[special.mail.example A 10.2.0.1]", answers(ask("special.mail.example", DNS.A)).toString());
	}

	@Test
	public void errorsAreReported() throws Exception {
		write(settings, "domains=good.example,not_a domain!\n");
		server.loadZones();
		String errors = String.join("\n", server.getZoneErrors());
		assertTrue(errors.contains("not a domain name"), errors);
		// the rest is served
		assertNotNull(server.getZone("good.example"));
	}

	@Test
	public void withoutASharedZoneTheListedDomainsArentServed() throws Exception {
		System.clearProperty(DnsServer.PROP_SHARED_ZONE);
		DnsServer none = new DnsServer();
		none.loadZones();
		assertNull(none.getZone("mail.example"));
		assertTrue(String.join("\n", none.getZoneErrors()).contains(DnsServer.PROP_SHARED_ZONE+" is not set"), none.getZoneErrors().toString());
		// a zone with a file is still served, from its own records
		assertNotNull(none.getZone("child.test"));
	}

	@Test
	public void anotherSettingCanHoldTheList() throws Exception {
		write(settings, "domains=mail.example\nzones=other.example\n");
		String saved = System.getProperty(DnsServer.PROP_DOMAIN_LIST+".key");
		System.setProperty(DnsServer.PROP_DOMAIN_LIST+".key", "zones");
		try {
			DnsServer other = new DnsServer();
			other.loadZones();
			assertNotNull(other.getZone("other.example"));
			assertNull(other.getZone("mail.example"));
			assertEquals("[other.example]", other.getListedDomains().toString());
		} finally {
			restore(DnsServer.PROP_DOMAIN_LIST+".key", saved);
		}
	}
}
