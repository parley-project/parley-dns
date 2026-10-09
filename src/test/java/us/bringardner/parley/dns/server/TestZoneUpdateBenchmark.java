package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Locale;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.Name;
import us.bringardner.parley.dns.RR;

/**
 * Benchmark for the zone's write path (what a dynamic update, RFC 2136, does):
 * exactRecords / addRecord / removeRecords. These used to scan every name of the
 * zone, lower-casing each one, so the cost of an update grew with the zone.
 *
 * Each case prints its timings, and compares the indexed path against the old
 * scan (re-implemented here over getNames()) in the same JVM, so the check does
 * not depend on the speed of the machine. Run just this with
 * <pre>mvn -pl parley-dns test -Dtest=TestZoneUpdateBenchmark</pre>
 */
public class TestZoneUpdateBenchmark {

	private static final int ZONE_NAMES = 20000;
	private static final int OPS = 2000;

	private static File dir;
	private static File zoneFile;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("zbench").toFile();
		zoneFile = new File(dir, "bench.test.txt");
		StringBuilder z = new StringBuilder();
		z.append("@\tIN\tSOA\tns1.bench.test. postmaster.bench.test. (\n"
				+ "\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
				+ "\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
				+ "\t\tNS\tns1\n"
				+ "ns1\tIN\tA\t10.0.0.53\n"
				+ "*.wild\tIN\tA\t10.0.0.1\n");
		for(int i=0; i < ZONE_NAMES; i++ ) {
			z.append("h"+i+"\tIN\tA\t10.1."+(i/250%250)+"."+(1+i%250)+"\n");
		}
		try(FileWriter w = new FileWriter(zoneFile)) {
			w.write(z.toString());
		}
	}

	@AfterAll
	public static void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static RR a(String name, int i) {
		A ret = new A(name);
		ret.setRdata(new byte[] {10, 9, (byte)(i>>8), (byte)i});
		return ret;
	}

	/** The write path as it was before the index: compare every name of the zone. */
	private static int scan(Zone z, String name) {
		String key = name.toLowerCase(Locale.ROOT);
		java.util.List<Name> names = z.getNames();
		for(int i=0; i < names.size(); i++ ) {
			if( names.get(i).toString().toLowerCase(Locale.ROOT).equals(key) ) {
				return i;
			}
		}
		return -1;
	}

	private static double ms(long nanos) {
		return nanos/1_000_000.0;
	}

	@Test
	public void lookupByName() throws IOException {
		Zone z = new Zone(zoneFile);
		assertTrue(z.getNames().size() > ZONE_NAMES);
		String [] probes = new String[OPS];
		for(int i=0; i < OPS; i++ ) {
			// spread over the zone, the scan's cost depends on how far in the name is
			probes[i] = "H"+((i*7919)%ZONE_NAMES)+".bench.test";
		}

		// warm up
		for(int i=0; i < 200; i++ ) {
			z.exactRecords(probes[i]);
		}

		long t0 = System.nanoTime();
		int found = 0;
		for(String p : probes) {
			if( !z.exactRecords(p).isEmpty() ) {
				found++;
			}
		}
		long indexed = System.nanoTime() - t0;

		int scanOps = 100;
		t0 = System.nanoTime();
		int scanFound = 0;
		for(int i=0; i < scanOps; i++ ) {
			if( scan(z, probes[i]) >= 0 ) {
				scanFound++;
			}
		}
		long scanned = (System.nanoTime() - t0) * OPS / scanOps;

		System.out.printf("[zone bench] exactRecords x%d on %d names: indexed %.1f ms, scan %.1f ms (%.0fx)%n",
				OPS, z.getNames().size(), ms(indexed), ms(scanned), (double)scanned/Math.max(1, indexed));
		assertEquals(OPS, found);
		assertEquals(scanOps, scanFound);
		assertTrue(indexed < scanned, "indexed lookup should beat scanning the zone");
	}

	@Test
	public void dynamicUpdates() throws IOException {
		Zone z = new Zone(zoneFile);
		int before = z.getNames().size();

		long t0 = System.nanoTime();
		// what an UPDATE does for each new name: look it up, add it, then a query sees it
		for(int i=0; i < OPS; i++ ) {
			String n = "dyn"+i+".bench.test";
			assertTrue(z.exactRecords(n).isEmpty());
			z.addRecord(a(n, i));
			assertEquals(1, z.exactRecords(n).size());
		}
		long added = System.nanoTime() - t0;
		assertEquals(before + OPS, z.getNames().size());

		// more records on names that already exist must not cost a rebuild of the query index
		t0 = System.nanoTime();
		for(int i=0; i < OPS; i++ ) {
			z.addRecord(a("h"+i+".bench.test", i));
		}
		long existing = System.nanoTime() - t0;
		assertEquals(2, z.exactRecords("h5.bench.test").size());

		t0 = System.nanoTime();
		int removed = 0;
		for(int i=0; i < 200; i++ ) {
			removed += z.removeRecords("dyn"+i+".bench.test", r -> true);
		}
		long removal = System.nanoTime() - t0;
		assertEquals(200, removed);
		assertTrue(z.exactRecords("dyn0.bench.test").isEmpty());
		assertEquals(1, z.exactRecords("dyn300.bench.test").size());

		System.out.printf("[zone bench] %d adds of new names: %.1f ms; %d adds to existing names: %.1f ms; 200 removals: %.1f ms%n",
				OPS, ms(added), OPS, ms(existing), ms(removal));
	}

	@Test
	public void queriesStayCorrectAfterUpdates() throws IOException {
		Zone z = new Zone(zoneFile);
		assertEquals(null, z.getMatchingRRs(new Name("late.bench.test")));
		z.addRecord(a("late.bench.test", 1));
		assertEquals(1, z.getMatchingRRs(new Name("LATE.bench.test")).size());
		assertEquals(1, z.getMatchingRRs(new Name("x.wild.bench.test")).size(), "wildcard still applies");
		z.removeRecords("late.bench.test", r -> true);
		assertEquals(null, z.getMatchingRRs(new Name("late.bench.test")));
	}
}
