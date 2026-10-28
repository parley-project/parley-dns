/**
 * <PRE>
 * 
 * Copyright Tony Bringarder 1998, 2025 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 * 
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *   
 *   
 *	@author Tony Bringardner   
 */
package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.Name;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Fixtures;

/**
 * Offline tests of the zone's lookup index: exact names, mixed case,
 * wildcards (RFC 4592, see also TestRfc4592Wildcards) and misses; the
 * empty non-terminal set agrees with a scan and is faster than one.
 */
public class TestZoneIndex {

	private static File dir;
	private static Zone big;
	private static Zone fixture;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("zidx").toFile();
		File f = new File(dir,"big.test.txt");
		StringBuilder z = new StringBuilder();
		z.append("@\tIN\tSOA\tns1.big.test. postmaster.big.test. (\n"
				+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
				+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
				+"\t\tNS\tns1\n"
				+"ns1\tIN\tA\t10.0.0.53\n"
				+"*.wild\tIN\tA\t10.0.0.1\n"
				+"exact.wild\tIN\tA\t10.0.0.3\n");
		for(int i=0; i< 5000; i++ ) {
			z.append("h"+i+"\tIN\tA\t10.1."+(i/250)+"."+(1+i%250)+"\n");
		}
		try(FileWriter w = new FileWriter(f)) {
			w.write(z.toString());
		}
		big = new Zone(f);
		fixture = new Zone(Fixtures.file("TestFiles/zones/foo.com.txt"));
	}

	@AfterAll
	public static void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	@Test
	public void lookups() {
		List<RR> wild = big.getMatchingRRs(new Name("*.wild.big.test"));
		assertNotNull(wild, "a query for the wildcard itself finds it");
		assertSame(wild, big.getMatchingRRs(new Name("anything.wild.big.test")));
		assertSame(wild, big.getMatchingRRs(new Name("a.b.wild.big.test")), "a '*' stands for any number of labels");
		List<RR> exact = big.getMatchingRRs(new Name("exact.wild.big.test"));
		assertNotNull(exact);
		assertNotSame(wild, exact, "an existing name is never matched by a wildcard");
		assertSame(exact, big.getMatchingRRs(new Name("EXACT.Wild.big.test")));
		assertNull(big.getMatchingRRs(new Name("wild.big.test")), "an empty non-terminal owns nothing");
		assertNull(big.getMatchingRRs(new Name("below.exact.wild.big.test")), "no *.exact.wild.big.test");
		assertNotNull(big.getMatchingRRs(new Name("h4999.big.test")));
		assertSame(big.getMatchingRRs(new Name("h2500.big.test")), big.getMatchingRRs(new Name("H2500.BIG.test")));
		assertNull(big.getMatchingRRs(new Name("nope.big.test")));
		assertNull(big.getMatchingRRs(new Name("h5000.big.test")));
		assertNull(big.getMatchingRRs(new Name("big.testx")));
	}

	@Test
	public void theOldPatternsAreOrdinaryNames() {
		// foo.com's *.*., *.*.*., dev.*.*. and dns2.*.*. no longer match by label count
		assertNotNull(fixture.getMatchingRRs(new Name("www.foo.com")));
		assertNull(fixture.getMatchingRRs(new Name("xxx.com")));
		assertNull(fixture.getMatchingRRs(new Name("dev.xxx.com")));
		assertNull(fixture.getMatchingRRs(new Name("a.b.c.d")));
		assertTrue(fixture.getLoadWarnings().size() > 0, "they load with a warning");
	}

	private static final String [] BELOW = {
			"big.test", "test", "BIG.Test", "h1.big.test", "wild.big.test", "x.wild.big.test", "nope.big.test",
			"b.big.test", "c.b.big.test", "d.c.b.big.test", "c.B.big.test", "foo.com", "com", "xxx.com", "*.big.test",
			"", ".big.test", "big.test.", "ig.test", "a.b.c.d"
	};

	private static void assertBelowSameAsScan(Zone z) {
		for(String n : BELOW) {
			assertEquals(z.linearHasNamesBelow(n), z.hasNamesBelow(n), "'"+n+"'");
		}
	}

	@Test
	public void namesBelowSameAsTheScan() throws IOException {
		//  Empty non-terminals: NODATA for them, NXDOMAIN for names that don't exist
		assertBelowSameAsScan(big);
		assertBelowSameAsScan(fixture);
		assertEquals(true, big.hasNamesBelow("big.test"));
		assertEquals(true, big.hasNamesBelow("wild.big.test"), "exact.wild is below it");
		assertEquals(false, big.hasNamesBelow("h1.big.test"));
		//  Kept up to date when records are added and removed
		Zone z = big.copyForUpdate();
		us.bringardner.parley.dns.A a = new us.bringardner.parley.dns.A("d.c.b.big.test");
		a.setAddress("10.9.9.9");
		z.addRecord(a);
		assertBelowSameAsScan(z);
		assertEquals(true, z.hasNamesBelow("B.big.test"));
		z.removeRecords("d.c.b.big.test", r -> true);
		assertBelowSameAsScan(z);
		assertEquals(false, z.hasNamesBelow("b.big.test"));
	}

	@Test
	public void namesBelowIsFast() {
		//  It compared the name with every name in the zone (5000 here) per NXDOMAIN
		long t0 = System.nanoTime();
		for(int i=0; i < 2000; i++ ) {
			big.linearHasNamesBelow("nope"+i+".big.test");
		}
		long scan = System.nanoTime()-t0;
		t0 = System.nanoTime();
		for(int i=0; i < 2000; i++ ) {
			big.hasNamesBelow("nope"+i+".big.test");
		}
		long indexed = System.nanoTime()-t0;
		System.out.println("5000-name zone, 2000 hasNamesBelow: scan "+(scan/1_000_000)+" ms, indexed "+(indexed/1_000_000)+" ms");
		assertEquals(true, indexed < scan, "the set lookup should beat the scan");
	}


}
