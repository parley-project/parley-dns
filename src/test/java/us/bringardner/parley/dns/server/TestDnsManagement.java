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
	public void editTheSharedZone() throws Exception {
		File f = new File(dir, "shared.zone");
		assertEquals(f.getAbsolutePath(), bean.getSharedZoneFile());
		String before = bean.getSharedZoneText();
		assertEquals(TestInheritedZones.primary(10, ""), before);

		//  a record added (sent with \r\n line ends, as a browser does): the inheriting zone serves it at once
		String after = TestInheritedZones.primary(11, "added\tIN\tA\t10.9.9.9\n");
		bean.setSharedZoneText(after.replace("\n", "\r\n"), before);
		assertEquals(after, new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
		assertEquals(after, bean.getSharedZoneText());
		assertEquals(before, new String(Files.readAllBytes(new File(dir, "shared.zone.previous").toPath()), StandardCharsets.UTF_8));
		assertEquals("[A 10.9.9.9 (inherited)]", records("child.test", "added.child.test").toString());
		assertEquals(16, zone("child.test").getSerial());

		//  refused, and the file left as it is: the serial not raised, not a zone, a $INHERIT line,
		//  an empty text, and a change made since the text was read
		assertThrows(IllegalArgumentException.class, () -> bean.setSharedZoneText(TestInheritedZones.primary(11, "x\tIN\tA\t10.0.0.1\n"), after));
		assertThrows(IllegalArgumentException.class, () -> bean.setSharedZoneText("not a zone\n", after));
		assertThrows(IllegalArgumentException.class, () -> bean.setSharedZoneText("$INHERIT\n"+TestInheritedZones.primary(12, ""), after));
		assertThrows(IllegalArgumentException.class, () -> bean.setSharedZoneText("  \n", after));
		assertThrows(IllegalStateException.class, () -> bean.setSharedZoneText(TestInheritedZones.primary(12, ""), before));
		assertEquals(after, bean.getSharedZoneText());
		assertEquals("[A 10.9.9.9 (inherited)]", records("child.test", "added.child.test").toString());

		//  null for expected: whatever is there is replaced
		bean.setSharedZoneText(TestInheritedZones.primary(12, ""), null);
		assertEquals("[]", records("child.test", "added.child.test").toString());
		assertEquals(0, bean.getErrors().length);
	}

	@Test
	public void noSharedZone() throws Exception {
		System.clearProperty(DnsServer.PROP_SHARED_ZONE);
		server.loadZones();
		assertNull(bean.getSharedZoneFile());
		assertThrows(IllegalStateException.class, () -> bean.getSharedZoneText());
		assertThrows(IllegalStateException.class, () -> bean.setSharedZoneText(TestInheritedZones.primary(11, ""), null));
	}

	@Test
	public void unregisteredWhenStopped() throws Exception {
		ObjectName n = new ObjectName("us.bringardner.parley:type=Dns,name=DnsServer");
		assertTrue(mbeans.isRegistered(n));
		server.stop();
		assertFalse(mbeans.isRegistered(n));
	}
}
