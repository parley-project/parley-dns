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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
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
 * parley.dns.mailSettings: the mail domains are served as zones inheriting from the master zone with
 * no zone file, they inherit the master zone's DKIM record (the shared key) while the DKIM keys in
 * the settings aren't served, and their DMARC report authorizations are served.
 */
public class TestMailDomains {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static final int REFUSED = 5;
	private static final int NXDOMAIN = 3;
	private File dir;
	private File keys;
	private File settings;
	private DnsServer server;
	private String savedDir;
	private String savedDefault;
	private String savedSettings;
	private KeyPair key2;

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("maildomains").toFile();
		keys = Files.createTempDirectory("maildkim").toFile();
		write(new File(dir, "primary.test.txt"), TestInheritedZones.primary(10, "mx1._domainkey\tIN\tTXT\t\"v=DKIM1; k=rsa; p=SHARED\"\n"));
		write(new File(dir, "child.test.txt"), TestInheritedZones.child(5, ""));
		//  a key with the record text parley-mail-admin keeps beside it, and one without (made from the key)
		write(new File(keys, "mail.example-sel1.pem"), "-----BEGIN PRIVATE KEY-----\nnot read\n-----END PRIVATE KEY-----\n");
		write(new File(keys, "mail.example-sel1.pem.txt"), "v=DKIM1; k=rsa; p=AAAA\n");
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(2048);
		key2 = g.generateKeyPair();
		write(new File(keys, "child.test-s2.pem"), "-----BEGIN PRIVATE KEY-----\n"
				+Base64.getMimeEncoder().encodeToString(key2.getPrivate().getEncoded())+"\n-----END PRIVATE KEY-----\n");
		settings = new File(keys, "queue.properties");
		settings("primary.test,child.test,Mail.Example.");
		savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		savedSettings = System.getProperty(DnsServer.PROP_MAIL_SETTINGS);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "primary.test");
		System.setProperty(DnsServer.PROP_MAIL_SETTINGS, settings.getAbsolutePath());
		server = new DnsServer();
		server.loadZones();
		server.setRecursionAvailable(false);
		server.setUpdateAllow("127.0.0.1");
	}

	private void settings(String domains) throws IOException {
		write(settings, "hostname=mx1.primary.test\n"
				+"domains="+domains+"\n"
				+"dkim.keys=mail.example:sel1:"+new File(keys, "mail.example-sel1.pem")
				+",child.test:s2:"+new File(keys, "child.test-s2.pem")+"\n");
	}

	@AfterEach
	public void cleanup() {
		restore(DnsServer.PROP_ZONE_DIR, savedDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedDefault);
		restore(DnsServer.PROP_MAIL_SETTINGS, savedSettings);
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
	public void aMailDomainIsServedFromTheMasterZoneWithNoFile() {
		Zone z = server.getZone("mail.example");
		assertNotNull(z, "served");
		assertTrue(z.getOwn().isVirtual());
		assertEquals("primary.test", z.getOwn().getInheritFrom());
		assertFalse(new File(dir, "mail.example.txt").exists(), "no zone file");

		Message m = ask("mail.example", DNS.MX);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertTrue(m.isAuthority());
		assertEquals("[mail.example MX 10 mx1.primary.test.]", answers(m).toString());
		assertEquals("[mx1.mail.example A 10.0.0.25]", answers(ask("mx1.mail.example", DNS.A)).toString());
		assertEquals("\"v=spf1 mx -all\"", answers(ask("mail.example", DNS.TXT)).get(0).replace("mail.example TXT ", ""));
		assertEquals("[_dmarc.mail.example TXT \"v=DMARC1; p=quarantine\"]", answers(ask("_dmarc.mail.example", DNS.TXT)).toString());
		Message soa = ask("mail.example", DNS.SOA);
		assertEquals(1, soa.getAnswerCount());
		assertEquals("mail.example", strip(soa.getAnswer().get(0).getName()));

		// a domain with a zone of its own keeps it; one that isn't listed isn't served
		assertFalse(server.getZone("child.test").getOwn().isVirtual());
		assertEquals(REFUSED, ask("other.example", DNS.MX).getResponseCode());

		// on the admin's DNS page: a zone with no file
		DnsServerManagement mgmt = new DnsServerManagement(server);
		boolean found = false;
		for(DnsZoneInfo i : mgmt.getZones()) {
			if( i.getName().equals("mail.example") ) {
				found = true;
				assertEquals("primary.test", i.getInheritFrom());
				assertNull(i.getFile());
			}
		}
		assertTrue(found);
	}

	@Test
	public void theSharedKeysRecordIsInheritedAndTheSettingsKeysArentServed() throws Exception {
		// every mail domain, with or without a zone file, inherits the master zone's DKIM record (the shared key)
		assertEquals("v=DKIM1; k=rsa; p=SHARED", txt(ask("mx1._domainkey.primary.test", DNS.TXT)));
		assertEquals("v=DKIM1; k=rsa; p=SHARED", txt(ask("mx1._domainkey.mail.example", DNS.TXT)));
		assertEquals("v=DKIM1; k=rsa; p=SHARED", txt(ask("mx1._domainkey.child.test", DNS.TXT)));
		// the keys in dkim.keys aren't served from the settings: a domain's own key goes in its own zone
		assertEquals(NXDOMAIN, ask("sel1._domainkey.mail.example", DNS.TXT).getResponseCode());
		assertEquals(NXDOMAIN, ask("s2._domainkey.child.test", DNS.TXT).getResponseCode());
		// and a change to a key's files doesn't reload anything
		write(new File(keys, "mail.example-sel1.pem.txt"), "v=DKIM1; k=rsa; p=BBBB\n");
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
		assertEquals("[mail.example MX 10 mx1.primary.test.]", answers(ask("mail.example", DNS.MX)).toString());

		// read back from the file: the same zone, now with a file
		assertTrue(server.shouldReloadZones());
		server.loadZones();
		Zone z = server.getZone("mail.example");
		assertFalse(z.getOwn().isVirtual());
		assertEquals("primary.test", z.getOwn().getInheritFrom());
		assertEquals("[special.mail.example A 10.2.0.1]", answers(ask("special.mail.example", DNS.A)).toString());

		// with a file it stays served when it leaves the list (its own records override the master's)
		settings("primary.test,child.test");
		server.loadZones();
		assertEquals("[special.mail.example A 10.2.0.1]", answers(ask("special.mail.example", DNS.A)).toString());
	}

	@Test
	public void errorsAreReported() throws Exception {
		write(settings, "domains=good.example,not_a domain!\ndkim.keys=good.example:s:"+new File(keys, "missing.pem")+",bad\n");
		server.loadZones();
		String errors = String.join("\n", server.getZoneErrors());
		assertTrue(errors.contains("not a domain name"), errors);
		// the rest is served
		assertNotNull(server.getZone("good.example"));
	}
}
