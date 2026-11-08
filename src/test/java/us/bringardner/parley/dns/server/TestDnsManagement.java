package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.management.JMX;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.ObjectName;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.dns.TestFiles;
import us.bringardner.parley.files.FileSource;

/** The DNS server's management bean, used as a JMX client would (through an MXBean proxy). */
public class TestDnsManagement {

	@TempDir
	static Path tmp;

	private FileSource dir;
	private DnsServer server;
	private MBeanServer mbeans;
	private DnsServerMXBean bean;
	private String savedDir;
	private String savedDefault;
	private String savedShared;

	@BeforeEach
	public void setup() throws Exception {
		dir = TestFiles.newFolder(tmp, "dnsjmx");
		write("primary.test.txt", TestInheritedZones.primary(10, ""));
		write("child.test.txt", TestInheritedZones.child(5, ""));
		write("shared.zone", TestInheritedZones.primary(10, ""));
		savedDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedDefault = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		savedShared = System.getProperty(DnsServer.PROP_SHARED_ZONE);
		System.setProperty(DnsServer.PROP_SHARED_ZONE, dir.getChild("shared.zone").getAbsolutePath());
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
	}

	private static void restore(String key, String value) {
		if( value == null ) {
			System.clearProperty(key);
		} else {
			System.setProperty(key, value);
		}
	}

	private void write(String name, String text) throws IOException {
		try(Writer w = TestFiles.writer(dir.getChild(name))) {
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
	public void zonesAndRecords() throws Exception {
		assertEquals("STOPPED", bean.getState());
		assertEquals(0, bean.getStarted());
		assertEquals(dir.getCanonicalPath(), FileSource.of(bean.getZoneDirectory()).getCanonicalPath());

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
		dir.getChild("shared.zone").setLastModified(System.currentTimeMillis()+5000);
		bean.reload();
		String errors = String.join("\n", bean.getErrors());
		assertTrue(errors.contains("broken.test.txt: "), errors);
		assertTrue(errors.contains("shared zone: ") && errors.contains("shared.zone"), errors);
		dir.getChild("broken.test.txt").delete();
		write("shared.zone", TestInheritedZones.primary(11, ""));
		dir.getChild("shared.zone").setLastModified(System.currentTimeMillis()+10000);
		bean.reload();
		assertEquals(0, bean.getErrors().length, String.join("\n", bean.getErrors()));
	}

	@Test
	public void aNewInheritingZoneFileIsServedAfterAReload() throws Exception {
		// the server writes no zone file: whoever manages them does (SharedZoneText gives the text)
		String shared = new String(TestFiles.bytes(dir.getChild("shared.zone")), StandardCharsets.UTF_8);
		String text = SharedZoneText.inheritingZone("New.Example.", shared, dir);
		assertTrue(text.contains("$INHERIT\n"), text);
		write("new.example.txt", text);
		bean.reload();
		DnsZoneInfo z = zone("new.example");
		assertEquals(Zone.SHARED, z.getInheritFrom());
		assertEquals(0, z.getOwnRecords());
		assertEquals(11, z.getSerial());
		assertEquals("[A 10.0.0.80 (inherited)]", records("new.example", "www.new.example").toString());
		// the shared zone's SOA, read under the new domain's name
		assertEquals("ns1.new.example", server.getZone("new.example").getSoa().getMname());
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
		FileSource f = dir.getChild("shared.zone");
		assertEquals(f.getAbsolutePath(), bean.getSharedZoneFile());
		List<String> recs = shared();
		assertTrue(recs.get(0).startsWith("@ SOA ") && recs.get(0).contains(" ns1 postmaster 10 3600 1800 1209600 300"), recs.get(0));
		assertTrue(recs.contains("@ MX 300 10 mx1"), recs.toString());
		assertTrue(recs.contains("*.wild A 300 10.0.0.99"), recs.toString());
		assertTrue(recs.contains("webmail CNAME 300 www"), recs.toString());
		assertTrue(recs.contains("_dmarc TXT 300 \"v=DMARC1; p=quarantine\""), recs.toString());
		assertEquals(1, recs.stream().filter(r -> r.contains(" SOA ")).count(), recs.toString());

		//  the file rewritten from its records (as a managing program would), a record added: served
		//  by the inheriting zone after a reload
		List<SharedZoneText.Record> list = new ArrayList<SharedZoneText.Record>(
				SharedZoneText.records(new String(TestFiles.bytes(f), StandardCharsets.UTF_8)));
		SharedZoneText.Record soa = list.get(0);
		list.set(0, new SharedZoneText.Record("@", soa.getTtl(), "SOA", soa.getData().replace(" 10 3600", " 11 3600")));
		list.add(new SharedZoneText.Record("ftp", 600, "A", "10.0.0.21"));
		String text = SharedZoneText.text(list, "; written by a test\n");
		assertEquals(11, SharedZoneText.check(text));
		write("shared.zone", text);
		bean.reload();
		assertEquals("[A 10.0.0.21 (inherited)]", records("child.test", "ftp.child.test").toString());
		assertEquals(16, zone("child.test").getSerial());
		assertTrue(shared().contains("ftp A 600 10.0.0.21"), shared().toString());
		assertEquals(recs.size()+1, shared().size(), "the same records, round trip, plus the one added");
	}

	@Test
	public void aSharedZoneWithAnIncludeIsReadFromItsFolder() throws Exception {
		write("common.inc", "ftp\tIN\tA\t10.0.0.21\n");
		write("shared.zone", TestInheritedZones.primary(11, "$INCLUDE common.inc\n"));
		bean.reload();
		assertTrue(shared().contains("ftp A 300 10.0.0.21"), shared().toString());
		String shared = new String(TestFiles.bytes(dir.getChild("shared.zone")), StandardCharsets.UTF_8);
		assertTrue(SharedZoneText.inheritingZone("new.example", shared, dir).contains("$INHERIT"));
		assertEquals(11, SharedZoneText.check(shared, dir));
	}

	@Test
	public void aSharedZoneTextIsCheckedAsTheServerChecksTheFile() {
		String good = TestInheritedZones.primary(10, "");
		assertThrows(IOException.class, () -> SharedZoneText.check(good+"x\tIN\tMX\tten mail\n"), "not MX data");
		assertThrows(IOException.class, () -> SharedZoneText.check("$INHERIT\n"+good), "no $INHERIT");
		assertThrows(IllegalArgumentException.class, () -> SharedZoneText.editableType("RRSIG"), "signing makes it");
		assertThrows(IllegalArgumentException.class, () -> SharedZoneText.editableType("BOGUS"));
		assertEquals("CNAME", SharedZoneText.editableType(" cname "));
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
	}

	@Test
	public void unregisteredWhenStopped() throws Exception {
		ObjectName n = new ObjectName("us.bringardner.parley:type=Dns,name=DnsServer");
		assertTrue(mbeans.isRegistered(n));
		server.stop();
		assertFalse(mbeans.isRegistered(n));
	}
}
