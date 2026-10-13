package us.bringardner.parley.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.Cname;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Ds;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Ns;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Section;
import us.bringardner.parley.dns.dnssec.DnssecKey;
import us.bringardner.parley.dns.server.DnsServer;

/**
 * Round 5 #83: a SECURE answer went out with the AD bit although only the
 * query name's RRsets (and the CNAME chain) had been validated. Records added
 * on the way (an A record for another name in the answer section, NS records
 * in the authority section) were passed on as if authenticated. Now only the
 * validated RRsets go out with a SECURE answer.
 */
public class TestValidatedOnly {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private final AtomicLong now = new AtomicLong(System.currentTimeMillis()/1000);
	private volatile UnaryOperator<Message> tamper = UnaryOperator.identity();
	private DnsServer server;
	private DnssecKey anchorKey;
	private Validator v;

	@BeforeEach
	public void setup() throws Exception {
		File dir = Files.createTempDirectory("validonly").toFile();
		server = new DnsServer();
		anchorKey = TestValidator.hierarchy(dir, server);
		v = new Validator(this::ask, now::get, Validator.parseAnchors("test. IN DS "
				+anchorKey.toDs(Ds.SHA256, 0).getRdataAsString()), 1000);
	}

	private Message ask(Section q) {
		Message m = new Message();
		m.setQuestion(q.getName(), q.getType(), DNS.IN);
		m.addAdditional(us.bringardner.parley.dns.Edns.newOpt(0, true));
		List<Message> r = server.query(new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(m.toByteArray()))));
		return tamper.apply(new Message(new ByteBuffer(r.get(0).toByteArray())));
	}

	/** A client query with DO, as the server would see it. */
	private static QueryData client(String name, int type) {
		Message m = new Message();
		m.setQuestion(name, type, DNS.IN);
		m.getHeader().setRD(true);
		m.addAdditional(us.bringardner.parley.dns.Edns.newOpt(0, true));
		return new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(m.toByteArray())));
	}

	/** Validate the answer to (name, type) and shape it for a DO client. */
	private Message answer(String name, int type, Validator.Status expect) {
		Section q = new Section(name, type, DNS.IN);
		Message m = ask(q);
		Validator.Result r = v.validate(m, q);
		assertEquals(expect, r.status, r.toString());
		ResolverThread.finish(m, client(name, type), r, false);
		return m;
	}

	private static boolean has(List<RR> section, String name, int type) {
		for(RR rr : section) {
			if( rr.getName().replaceAll("\\.$", "").equalsIgnoreCase(name) && rr.getType() == type ) {
				return true;
			}
		}
		return false;
	}

	private static boolean covered(List<RR> section, String name, int type) {
		for(RR rr : section) {
			if( rr instanceof us.bringardner.parley.dns.Rrsig && ((us.bringardner.parley.dns.Rrsig)rr).getTypeCovered() == type
					&& rr.getName().replaceAll("\\.$", "").equalsIgnoreCase(name) ) {
				return true;
			}
		}
		return false;
	}

	@Test
	public void injectedRecordsAreRemovedFromASecureAnswer() {
		tamper = m -> {
			Section q = m.getFirstQuestion();
			if( q != null && q.getName().equalsIgnoreCase("www.sec.test") && q.getType() == DNS.A ) {
				A evil = new A("bank.example", DNS.IN);
				evil.setTTL(86400);
				evil.setAddress("6.6.6.6");
				m.addAnswer(evil);
				Ns ns = new Ns("sec.test", DNS.IN);
				ns.setTTL(86400);
				ns.setNs("evil.example");
				m.addAuthority(ns);
			}
			return m;
		};
		Message m = answer("www.sec.test", DNS.A, Validator.Status.SECURE);
		assertTrue(m.getHeader().getAD(), "still SECURE");
		assertFalse(has(m.getAnswer(), "bank.example", DNS.A), "the unsigned A record used to go out under AD");
		assertFalse(has(m.getAuthority(), "sec.test", DNS.NS), "the unsigned NS record too");
		assertTrue(has(m.getAnswer(), "www.sec.test", DNS.A));
		assertTrue(covered(m.getAnswer(), "www.sec.test", DNS.A), "its RRSIG is kept for the DO client");
	}

	@Test
	public void aCnameChainIsKept() {
		Message m = answer("alias.sec.test", DNS.A, Validator.Status.SECURE);
		assertTrue(m.getHeader().getAD());
		assertTrue(has(m.getAnswer(), "alias.sec.test", DNS.CNAME));
		assertTrue(covered(m.getAnswer(), "alias.sec.test", DNS.CNAME));
		assertTrue(has(m.getAnswer(), "www.sec.test", DNS.A));
	}

	@Test
	public void anUnsignedSecondCnameMakesTheAnswerBogus() {
		tamper = m -> {
			Section q = m.getFirstQuestion();
			if( q != null && q.getName().equalsIgnoreCase("alias.sec.test") && q.getType() == DNS.A ) {
				Cname c = new Cname("alias.sec.test");
				c.setCname("evil.example");
				c.setTTL(300);
				m.addAnswer(c);
			}
			return m;
		};
		Message m = answer("alias.sec.test", DNS.A, Validator.Status.BOGUS);
		assertFalse(m.getHeader().getAD());
	}

	@Test
	public void aNegativeAnswerKeepsItsProofAndSoa() {
		Message m = answer("nope.sec.test", DNS.A, Validator.Status.SECURE);
		assertTrue(m.getHeader().getAD());
		assertEquals(DNS.NAME_ERROR, m.getResponseCode());
		assertTrue(has(m.getAuthority(), "sec.test", DNS.SOA), "negative caching needs the SOA (RFC 2308)");
		assertTrue(covered(m.getAuthority(), "sec.test", DNS.SOA));
		boolean nsec = false;
		for(RR rr : m.getAuthority()) {
			nsec |= rr.getType() == DNS.NSEC;
		}
		assertTrue(nsec, "the NSEC proof stays");
	}

	@Test
	public void aWildcardAnswerKeepsItsProof() {
		Message m = answer("x.y.wild.sec.test", DNS.A, Validator.Status.SECURE);
		assertTrue(m.getHeader().getAD());
		assertTrue(has(m.getAnswer(), "x.y.wild.sec.test", DNS.A));
		boolean nsec = false;
		for(RR rr : m.getAuthority()) {
			nsec |= rr.getType() == DNS.NSEC;
		}
		assertTrue(nsec, "the proof that x.y.wild.sec.test itself doesn't exist stays");
	}

	@Test
	public void insecureAnswersAreLeftAlone() {
		tamper = m -> {
			Section q = m.getFirstQuestion();
			if( q != null && q.getName().equalsIgnoreCase("www.insecure.test") ) {
				A extra = new A("other.insecure.test", DNS.IN);
				extra.setTTL(300);
				extra.setAddress("10.9.9.9");
				m.addAnswer(extra);
			}
			return m;
		};
		Message m = answer("www.insecure.test", DNS.A, Validator.Status.INSECURE);
		assertFalse(m.getHeader().getAD());
		assertTrue(has(m.getAnswer(), "other.insecure.test", DNS.A), "no AD, nothing is claimed: passed on as before");
	}
}
