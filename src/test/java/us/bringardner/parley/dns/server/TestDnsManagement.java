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

	@BeforeEach
	public void setup() throws Exception {
		dir = Files.createTempDirectory("dnsjmx").toFile();
		write("primary.test.txt", TestInheritedZones.primary(10, ""));
		write("child.test.txt", TestInheritedZones.child(5, ""));
		savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
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
		assertEquals("primary.test", c.getInheritFrom());
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
		write("orphan.test.txt", "$INHERIT nowhere.test\n@ IN SOA ns1 postmaster ( 1 3600 1800 1209600 300 )\n");
		bean.reload();
		String errors = String.join("\n", bean.getErrors());
		assertTrue(errors.contains("broken.test.txt: "), errors);
		assertTrue(errors.contains("zone orphan.test: inherits from nowhere.test"), errors);
		new File(dir, "broken.test.txt").delete();
		write("orphan.test.txt", "@ IN SOA ns1 postmaster ( 2 3600 1800 1209600 300 )\n");
		new File(dir, "orphan.test.txt").setLastModified(System.currentTimeMillis()+5000);
		bean.reload();
		assertEquals(0, bean.getErrors().length, String.join("\n", bean.getErrors()));
	}

	@Test
	public void createInheritingZone() throws Exception {
		bean.createInheritingZone("New.Example.", "primary.test");
		File f = new File(dir, "new.example.txt");
		String text = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
		assertTrue(text.contains("$INHERIT primary.test.\n"), text);
		DnsZoneInfo z = zone("new.example");
		assertEquals("primary.test", z.getInheritFrom());
		assertEquals(0, z.getOwnRecords());
		assertEquals(11, z.getSerial());
		assertEquals("[A 10.0.0.80 (inherited)]", records("new.example", "www.new.example").toString());
		Zone served = server.getZone("new.example");
		assertEquals("ns1.primary.test", served.getSoa().getMname());

		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("new.example", "primary.test"));
		// an old journal of the name would be replayed into the new zone: refused
		write("old.example.txt.jnl", "base 1\nbegin\nadd ghost.old.example. 300 IN A 6.6.6.6\nend\n");
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("old.example", "primary.test"));
		assertFalse(new File(dir, "old.example.txt").exists());
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("other.example", "nowhere.test"));
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("../evil", "primary.test"));
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("bad_name.example", "primary.test"));
		// one level only
		assertThrows(IllegalArgumentException.class, () -> bean.createInheritingZone("grand.example", "child.test"));
	}

	@Test
	public void unregisteredWhenStopped() throws Exception {
		ObjectName n = new ObjectName("us.bringardner.parley:type=Dns,name=DnsServer");
		assertTrue(mbeans.isRegistered(n));
		server.stop();
		assertFalse(mbeans.isRegistered(n));
	}
}
