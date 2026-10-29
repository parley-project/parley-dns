package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import javax.management.JMX;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.ObjectName;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The DNS server's management bean, used as a JMX client would (through an MXBean proxy). */
public class TestDnsManagement {

	private File dir;
	private DnsServer server;
	private MBeanServer mbeans;
	private DnsServerMXBean bean;
	private String savedDir;
	private String savedDefault;
	private String savedShared;

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("dnsjmx").toFile();
		write("primary.test.txt", TestInheritedZones.primary(10, ""));
		write("child.test.txt", TestInheritedZones.child(5, ""));
		write("shared.zone", TestInheritedZones.primary(10, ""));
		savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		savedShared = System.getProperty(DnsServer.PROP_SHARED_ZONE);
		System.setProperty(DnsServer.PROP_SHARED_ZONE, new File(dir, "shared.zone").getAbsolutePath());
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "primary.test");
		server = new DnsServer();
		server.loadZones();
		mbeans = MBeanServerFactory.newMBeanServer();
		ObjectName n = server.registerManagement(mbeans, "DnsServer");
		assertEquals("us.bringardner.parley:type=Dns,name=DnsServer", n.toString());
		bean = JMX.newMXBeanProxy(mbeans, n, DnsServerMXBean.class);
	}

	@AfterEach
	public void cleanup() {
		server.stop();
		restore(DnsServer.PROP_ZONE_DIR, savedDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedDefault);
		restore(DnsServer.PROP_SHARED_ZONE, savedShared);
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
		try(FileWriter w = new FileWriter(new File(dir, name))) {
			w.write(text);
		}
	}

	private DnsZoneInfo zone(String name) {
		for(DnsZoneInfo z : bean.getZones()) {
			if( z.getName().equals(name) ) {
				return z;
			}
		}
		return null;
	}

	private List<String> records(String zone, String name) {
		List<String> ret = new ArrayList<String>();
		for(DnsRecordInfo r : bean.getRecords(zone)) {
			if( r.getName().equals(name) ) {
				ret.add(r.getType()+" "+r.getData()+(r.isInherited() ? " (inherited)" : ""));
			}
		}
		return ret;
	}

	@Test
	public void zonesAndRecords() {
		assertEquals("STOPPED", bean.getState());
		assertEquals(0, bean.getStarted());
		assertEquals(dir.getAbsoluteFile().toPath().normalize().toString(),
				new File(bean.getZoneDirectory()).toPath().normalize().toString());
		DnsZoneInfo p = zone("primary.test");
		assertNull(p.getInheritFrom());
		assertEquals(10, p.getSerial());
		assertEquals(p.getRecords(), p.getOwnRecords());
		DnsZoneInfo c = zone("child.test");
		assertEquals(Zone.SHARED, c.getInheritFrom());
		assertEquals(15, c.getSerial());
		assertEquals(5, c.getOwnSerial());
		assertTrue(c.getRecords() > c.getOwnRecords());
		assertFalse(c.isSigned());
		assertTrue(c.getFile().endsWith("child.test.txt"));

		assertEquals("[MX 20 other.example.]", records("child.test", "child.test").stream()
				.filter(r -> r.startsWith("MX")).collect(java.util.stream.Collectors.toList()).toString());
		assertEquals("[A 10.0.0.25 (inherited)]", records("child.test", "mx1.child.test").toString());
		assertEquals("[A 10.1.0.1]", records("child.test", "special.child.test").toString());
		assertThrows(IllegalArgumentException.class, () -> bean.getRecords("nowhere.test"));
		assertEquals(0, bean.getErrors().length);
	}

	@Test
	public void errorsAreReported() throws Exception {
		write("broken.test.txt", "@ IN SOA ns1 postmaster ( 1 3600 1800 1209600 300 )\nx IN BOGUS 1\n");
		write("shared.zone", TestInheritedZones.primary(11, "x IN BOGUS 1\n"));
		new File(dir, "shared.zone").setLastModified(System.currentTimeMillis()+5000);
		bean.reload();
		String errors = String.join("\n", bean.getErrors());
		assertTrue(errors.contains("broken.test.txt: "), errors);
		assertTrue(errors.contains("shared zone: ") && errors.contains("shared.zone"), errors);
		new File(dir, "broken.test.txt").delete();
		write("shared.zone", TestInheritedZones.primary(11, ""));
		new File(dir, "shared.zone").setLastModified(System.currentTimeMillis()+10000);
		bean.reload();
		assertEquals(0, bean.getErrors().length, String.join("\n", bean.getErrors()));
	}

	@Test
	public void createInheritingZone() throws Exception {
		bean.createInheritingZone("New.Example.");
		File f = new File(dir, "new.example.txt");
		String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
		assertTrue(text.contains("$INHERIT\n"), text);
		DnsZoneInfo z = zone("new.example");
		assertEquals(Zone.SHARED, z.getInheritFrom());
		assertEquals(0, z.getOwnRecords());
		assertEquals(11, z.getSerial());
		assertEquals("[A 10.0.0.80 (inherited)]", records("new.example", "www.new.example").toString());
		Zone served = server.getZone("new.example");
		// the shared zone's SOA, read under the new domain's name
		assertEquals("ns1.new.example", served.getSoa().getMname());

		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("new.example"));
		// an old journal of the name would be replayed into the new zone: refused
		write("old.example.txt.jnl", "base 1\nbegin\nadd ghost.old.example. 300 IN A 6.6.6.6\nend\n");
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("old.example"));
		assertFalse(new File(dir, "old.example.txt").exists());
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("../evil"));
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("bad_name.example"));
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("child.test"), "has a file already");
	}

	@Test
	public void recordTypes() {
		List<String> editable = new ArrayList<String>();
		List<String> signing = new ArrayList<String>();
		for(DnsRecordType t : bean.getRecordTypes()) {
			(t.isEditable() ? editable : signing).add(t.getName());
		}
		assertTrue(editable.containsAll(java.util.Arrays.asList("A", "AAAA", "CAA", "CNAME", "DS", "HINFO", "HTTPS", "MX", "NS",
				"PTR", "RP", "SOA", "SPF", "SRV", "SSHFP", "SVCB", "TXT")), editable.toString());
		assertEquals("[DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM]", signing.toString());
		//  each example is valid data of its type, and every editable type but SOA can be updated
		for(DnsRecordType t : bean.getRecordTypes()) {
			if( t.isEditable() ) {
				int type = us.bringardner.parley.dns.Utility.typeOf(t.getName());
				Zone.parseRecord("x.test.", 300, us.bringardner.parley.dns.DNS.IN, type, t.getExample());
				assertEquals(!t.getName().equals("SOA"), Zone.isUpdatableType(type), t.getName());
			}
		}
	}

	private List<String> shared() throws Exception {
		List<String> ret = new ArrayList<String>();
		for(DnsRecordInfo r : bean.getSharedRecords()) {
			ret.add(r.getName()+" "+r.getType()+" "+r.getTtl()+" "+r.getData());
		}
		return ret;
	}

	@Test
	public void sharedZoneRecords() throws Exception {
		File f = new File(dir, "shared.zone");
		assertEquals(f.getAbsolutePath(), bean.getSharedZoneFile());
		List<String> recs = shared();
		assertTrue(recs.get(0).startsWith("@ SOA ") && recs.get(0).contains(" ns1 postmaster 10 3600 1800 1209600 300"), recs.get(0));
		assertTrue(recs.contains("@ MX 300 10 mx1"), recs.toString());
		assertTrue(recs.contains("*.wild A 300 10.0.0.99"), recs.toString());
		assertTrue(recs.contains("webmail CNAME 300 www"), recs.toString());
		assertTrue(recs.contains("_dmarc TXT 300 \"v=DMARC1; p=quarantine\""), recs.toString());
		assertEquals(1, recs.stream().filter(r -> r.contains(" SOA ")).count(), recs.toString());

		//  added: served by the inheriting zone at once, the serial raised, the file before kept
		bean.addSharedRecords("FTP", "a", 600, new String[] { "10.0.0.21", " 10.0.0.22 ", "" });
		assertEquals("[A 10.0.0.21 (inherited), A 10.0.0.22 (inherited)]", records("child.test", "ftp.child.test").toString());
		assertTrue(shared().get(0).contains(" postmaster 11 "), shared().get(0));
		assertEquals(16, zone("child.test").getSerial());
		assertTrue(new File(dir, "shared.zone.previous").exists());
		String written = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
		assertTrue(written.startsWith(SharedZone.HEADER), written);
		//  adding one it has changes nothing but the TTL of the set
		bean.addSharedRecords("ftp", "A", 1200, new String[] { "10.0.0.21" });
		assertTrue(shared().contains("ftp A 1200 10.0.0.22"), shared().toString());

		//  every field of a record changed: name, type, TTL and data
		bean.changeSharedRecord("ftp", "A", "10.0.0.22", "files", "CNAME", 900, "www");
		assertEquals("[A 10.0.0.21 (inherited)]", records("child.test", "ftp.child.test").toString());
		assertTrue(shared().contains("files CNAME 900 www"), shared().toString());
		assertEquals(1, records("child.test", "files.child.test").size());

		//  the SOA: changed; a serial that isn't higher is raised past the file's
		String soa = bean.getSharedRecords()[0].getData();
		bean.changeSharedRecord("@", "SOA", soa, "@", "SOA", 300, "ns1 hostmaster 5 3600 1800 1209600 600");
		String now = shared().get(0);
		assertTrue(now.contains(" hostmaster 14 3600 1800 1209600 600"), now);

		bean.deleteSharedRecord("files", "CNAME", "www");
		assertEquals("[]", records("child.test", "files.child.test").toString());

		//  refused, and the file left as it was
		String before = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
		assertThrows(IllegalArgumentException.class, () -> bean.addSharedRecords("x", "MX", 300, new String[] { "ten mail" }), "not MX data");
		assertThrows(IllegalArgumentException.class, () -> bean.addSharedRecords("x.example.", "A", 300, new String[] { "10.0.0.1" }), "absolute");
		assertThrows(IllegalArgumentException.class, () -> bean.addSharedRecords("@", "SOA", 300, new String[] { soa }), "a second SOA");
		assertThrows(IllegalArgumentException.class, () -> bean.addSharedRecords("x", "RRSIG", 300, new String[] { "x" }), "signing makes it");
		assertThrows(IllegalArgumentException.class, () -> bean.addSharedRecords("x", "BOGUS", 300, new String[] { "x" }));
		assertThrows(IllegalArgumentException.class, () -> bean.addSharedRecords("x", "A", 300, new String[] { " " }), "no value");
		assertThrows(IllegalArgumentException.class, () -> bean.deleteSharedRecord("@", "SOA", now.substring(now.indexOf("SOA ")+8)));
		assertThrows(IllegalArgumentException.class, () -> bean.changeSharedRecord("ftp", "A", "10.0.0.21", "@", "SOA", 300, "a b 1 1 1 1 1"));
		assertThrows(IllegalStateException.class, () -> bean.deleteSharedRecord("nothere", "A", "10.0.0.1"), "not there");
		assertThrows(IllegalStateException.class, () -> bean.changeSharedRecord("ftp", "A", "10.0.0.99", "ftp", "A", 300, "10.0.0.98"));
		assertEquals(before, new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
		assertEquals(0, bean.getErrors().length);
	}

	@Test
	public void theSoaIsListedFirst() {
		DnsRecordInfo[] l = bean.getRecords("child.test");
		assertEquals("SOA", l[0].getType());
		assertEquals("child.test", l[0].getName());
		assertTrue(l[0].getData().endsWith(" 15 3600 1800 1209600 300"), l[0].getData());
		assertEquals(1, java.util.Arrays.stream(l).filter(r -> r.getType().equals("SOA")).count());
	}

	@Test
	public void noSharedZone() throws Exception {
		System.clearProperty(DnsServer.PROP_SHARED_ZONE);
		server.loadZones();
		assertNull(bean.getSharedZoneFile());
		assertThrows(IllegalStateException.class, () -> bean.getSharedRecords());
		assertThrows(IllegalStateException.class, () -> bean.addSharedRecords("x", "A", 300, new String[] { "10.0.0.1" }));
	}

	@Test
	public void unregisteredWhenStopped() throws Exception {
		ObjectName n = new ObjectName("us.bringardner.parley:type=Dns,name=DnsServer");
		assertTrue(mbeans.isRegistered(n));
		server.stop();
		assertFalse(mbeans.isRegistered(n));
	}
}
