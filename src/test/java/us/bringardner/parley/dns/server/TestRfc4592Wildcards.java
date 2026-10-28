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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Mx;
import us.bringardner.parley.dns.Name;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.resolve.QueryData;

/**
 * Wildcards as RFC 4592 defines them, in an unsigned zone: the example zone
 * of section 2.2.1 and the answers it lists, asked through the server (wire
 * format included); plus zone files with the old positional patterns
 * (*.*. and the like), which still load, with a warning.
 */
public class TestRfc4592Wildcards {

	private static File dir;
	private static Zone zone;
	private static DnsServer server;

	@BeforeAll
	public static void setup() throws IOException {
		dir = Files.createTempDirectory("rfc4592").toFile();
		File f = new File(dir,"example.txt");
		//  RFC 4592 2.2.1 (the SOA and SRV data filled in)
		try(FileWriter w = new FileWriter(f)) {
			w.write("$ORIGIN example.\n"
					+"example.\t3600\tIN\tSOA\tns.example.com. hostmaster.example. ( 1 3600 1800 1209600 300 )\n"
					+"example.\t3600\tNS\tns.example.com.\n"
					+"example.\t3600\tNS\tns.example.net.\n"
					+"*.example.\t3600\tTXT\t\"this is a wildcard\"\n"
					+"*.example.\t3600\tMX\t10 host1.example.\n"
					+"sub.*.example.\t3600\tTXT\t\"this is not a wildcard\"\n"
					+"host1.example.\t3600\tA\t192.0.2.1\n"
					+"_ssh._tcp.host1.example.\t3600\tSRV\t0 1 22 host1.example.\n"
					+"_ssh._tcp.host2.example.\t3600\tSRV\t0 1 22 host2.example.\n"
					+"subdel.example.\t3600\tNS\tns.example.com.\n"
					+"subdel.example.\t3600\tNS\tns.example.net.\n");
		}
		zone = new Zone(f);
		server = new DnsServer();
		server.addZone(zone);
		server.setRecursionAvailable(false);
	}

	@AfterAll
	public static void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static Message ask(String name, int type) {
		Message q = new Message();
		q.setQuestion(name, type, DNS.IN);
		Message r = server.query(new QueryData(InetAddress.getLoopbackAddress(), 5353, q)).get(0);
		return new Message(new ByteBuffer(r.toByteArray()));
	}

	private static int count(List<RR> list, int type) {
		int ret = 0;
		for(RR rr : list) {
			if( rr.getType() == type ) {
				ret++;
			}
		}
		return ret;
	}

	private static void assertNxdomain(String name, int type) {
		Message m = ask(name, type);
		assertEquals(DNS.NAME_ERROR, m.getResponseCode(), name+" should not exist");
		assertEquals(0, m.getAnswerCount(), name);
	}

	private static void assertNodata(String name, int type) {
		Message m = ask(name, type);
		assertEquals(DNS.NOERROR, m.getResponseCode(), name+" exists");
		assertEquals(0, m.getAnswerCount(), name+": no records of that type");
	}

	@Test
	public void wildcardAnswersUnderTheQueryName() {
		//  host3.example. MX: synthesized from *.example., owner host3.example.
		Message m = ask("host3.example", DNS.MX);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m.getAnswer(),DNS.MX));
		RR mx = m.getAnswer().get(0);
		assertEquals("host3.example", mx.getName().toLowerCase());
		assertEquals("host1.example", ((Mx)mx).getExchange().toLowerCase(), "record data is not changed");
		//  the exchange's address (not from a wildcard) in the additional section
		assertEquals(1, count(m.getAdditional(),DNS.A));
	}

	@Test
	public void wildcardWithoutTheTypeIsNodata() {
		//  host3.example. A: the wildcard matches, but has no A
		assertNodata("host3.example", DNS.A);
	}

	@Test
	public void wildcardStandsForSeveralLabels() {
		//  foo.bar.example. TXT: bar.example. doesn't exist, so the closest
		//  encloser is example. and *.example. answers
		Message m = ask("foo.bar.example", DNS.TXT);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m.getAnswer(),DNS.TXT));
		assertEquals("foo.bar.example", m.getAnswer().get(0).getName().toLowerCase());
	}

	@Test
	public void anExistingNameIsNeverMatchedByAWildcard() {
		//  host1.example. MX: host1 exists (it has an A), so NODATA
		assertNodata("host1.example", DNS.MX);
		//  sub.*.example. MX: it exists ('*' isn't its leftmost label: an ordinary name)
		assertNodata("sub.*.example", DNS.MX);
		//  _tcp.host1.example. is an empty non-terminal (RFC 4592 2.2.2): it exists
		assertNodata("_tcp.host1.example", DNS.TXT);
	}

	@Test
	public void noWildcardBelowTheClosestEncloserIsNxdomain() {
		//  _telnet._tcp.host1.example.: closest encloser _tcp.host1.example.,
		//  and *._tcp.host1.example. doesn't exist
		assertNxdomain("_telnet._tcp.host1.example", DNS.SRV);
		//  ghost.*.example.: closest encloser *.example., and *.*.example. doesn't exist
		assertNxdomain("ghost.*.example", DNS.MX);
	}

	@Test
	public void belowADelegationIsAReferral() {
		//  host.subdel.example.: below the zone cut, not matched by *.example.
		Message m = ask("host.subdel.example", DNS.A);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(0, m.getAnswerCount());
		assertEquals(2, count(m.getAuthority(),DNS.NS));
		assertFalse(m.getHeader().getAA(), "a referral is not authoritative");
	}

	@Test
	public void aQueryForTheWildcardItselfFindsIt() {
		Message m = ask("*.example", DNS.TXT);
		assertEquals(DNS.NOERROR, m.getResponseCode());
		assertEquals(1, count(m.getAnswer(),DNS.TXT));
		assertEquals("*.example", m.getAnswer().get(0).getName());
	}

	@Test
	public void zoneLookupAndRenamedCopies() {
		List<RR> l = zone.getMatchingRRs(new Name("host3.example"));
		assertNotNull(l);
		assertEquals("*.example", l.get(0).getName());
		assertTrue(Zone.isFromWildcard(l.get(0), "host3.example"));
		assertFalse(Zone.isFromWildcard(l.get(0), "*.example"));
		assertNull(zone.getMatchingRRs(new Name("_tcp.host1.example")), "an empty non-terminal owns nothing");
		assertTrue(zone.hasNamesBelow("_tcp.host1.example"));
		//  getMatchingRR gives a copy named after the name, the zone's record is unchanged
		RR mx = zone.getMatchingRR("a.b.example", DNS.MX);
		assertEquals("a.b.example", mx.getName());
		assertEquals("*.example", zone.getMatchingRRs(new Name("host3.example")).get(0).getName());
		//  outside the zone: no wildcard applies
		assertNull(zone.getMatchingRRs(new Name("host3.example.org")));
		//  sub.*.example. is a valid name, but in an older zone file it was a
		//  positional pattern: its meaning changed, so it gets the warning
		assertEquals(1, zone.getLoadWarnings().size(), zone.getLoadWarnings().toString());
		assertTrue(zone.getLoadWarnings().get(0).contains("sub.*.example."));
	}

	@Test
	public void aWildcardThatExistsOnlyAsAnEmptyNonTerminalIsNodata() throws IOException {
		File f = new File(dir,"ent.test.txt");
		try(FileWriter w = new FileWriter(f)) {
			w.write("@\tIN\tSOA\tns1.ent.test. postmaster.ent.test. ( 1 3600 1800 1209600 300 )\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"a.*\tIN\tA\t10.0.0.1\n");
		}
		Zone z = new Zone(f);
		//  *.ent.test. exists (a.*.ent.test. is below it) but owns nothing
		List<RR> l = z.getMatchingRRs(new Name("x.ent.test"));
		assertNotNull(l, "the wildcard exists");
		assertTrue(l.isEmpty(), "and has no records");
		assertEquals(1, z.getLoadWarnings().size(), "a.* was a pattern before: "+z.getLoadWarnings());
	}

	@Test
	public void positionalPatternsLoadWithAWarning() throws IOException {
		File f = new File(dir,"old.test.txt");
		try(FileWriter w = new FileWriter(f)) {
			w.write("@\tIN\tSOA\tns1.old.test. postmaster.old.test. ( 1 3600 1800 1209600 300 )\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n"
					+"*.*.\tIN\tA\t10.0.0.2\n"
					+"\tIN\tMX\t10 mail.old.test.\n"
					+"dev.*.*.\tIN\tA\t10.0.0.4\n"
					+"*.old.test.\tIN\tA\t10.0.0.9\n");
		}
		Zone z = new Zone(f);
		List<String> w = z.getLoadWarnings();
		assertEquals(2, w.size(), "one per name, not per record: "+w);
		assertTrue(w.get(0).contains("old.test.txt") && w.get(0).contains("line 4") && w.get(0).contains("*.*."), w.get(0));
		assertTrue(w.get(1).contains("line 6") && w.get(1).contains("dev.*.*."), w.get(1));
		//  the entries are ordinary names now: a 2-label name isn't matched by *.*.
		assertNull(z.getMatchingRRs(new Name("example.com")));
		assertNotNull(z.getMatchingRRs(new Name("*.*")), "it matches its literal name");
		//  and the real wildcard still works
		assertEquals("*.old.test", z.getMatchingRRs(new Name("x.y.old.test")).get(0).getName());
	}
}
