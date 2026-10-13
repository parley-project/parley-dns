package us.bringardner.parley.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Ds;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Rrsig;
import us.bringardner.parley.dns.Section;
import us.bringardner.parley.dns.dnssec.DnssecKey;
import us.bringardner.parley.dns.server.DnsServer;

/**
 * Round 5 #76 (KeyTrap, CVE-2023-50387): a validation may make at most
 * {@link Validator#MAX_VERIFICATIONS} signature checks, at most
 * {@link Validator#MAX_FAILED_VERIFICATIONS} of them failing. Before, every
 * RRSIG was tried against every matching key with no limit (2,000 bad
 * signatures in front of the good one took about 1.4 s for one answer).
 */
public class TestValidatorLimits {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private final AtomicLong now = new AtomicLong(System.currentTimeMillis()/1000);
	private volatile UnaryOperator<Message> tamper = UnaryOperator.identity();
	private DnsServer server;
	private DnssecKey anchorKey;

	@BeforeEach
	public void setup() throws Exception {
		File dir = Files.createTempDirectory("vlimits").toFile();
		server = new DnsServer();
		anchorKey = TestValidator.hierarchy(dir, server);
		tamper = UnaryOperator.identity();
	}

	private Message ask(Section q) {
		Message m = new Message();
		m.setQuestion(q.getName(), q.getType(), DNS.IN);
		m.addAdditional(us.bringardner.parley.dns.Edns.newOpt(0, true));
		List<Message> r = server.query(new QueryData(LOOPBACK, 5353, new Message(new ByteBuffer(m.toByteArray()))));
		return tamper.apply(new Message(new ByteBuffer(r.get(0).toByteArray())));
	}

	private Validator validator() {
		return new Validator(this::ask, now::get, Validator.parseAnchors("test. IN DS "
				+anchorKey.toDs(Ds.SHA256, 0).getRdataAsString()), 1000);
	}

	private Validator.Result check(Validator v, String name, int type) {
		Section q = new Section(name, type, DNS.IN);
		return v.validate(ask(q), q);
	}

	/** Put 'count' damaged copies of each RRSIG of the www.sec.test A answer in front of it. */
	private void badSignatures(int count) {
		badSignatures("www.sec.test", count);
	}

	/** The same for the answers to (qname, A). */
	private void badSignatures(String qname, int count) {
		tamper = m -> {
			Section q = m.getFirstQuestion();
			if( q == null || !q.getName().equalsIgnoreCase(qname) || q.getType() != DNS.A ) {
				return m;
			}
			List<RR> ans = new ArrayList<RR>();
			for(RR rr : m.getAnswer()) {
				if( rr instanceof Rrsig ) {
					for(int i=0; i < count; i++ ) {
						Rrsig c = (Rrsig)rr.copy();
						byte [] s = c.getSignature();
						s[5] ^= (byte)(i+1);
						s[40] ^= (byte)((i >> 3)+1);
						c.setSignature(s);
						ans.add(c);
					}
				}
			}
			ans.addAll(m.getAnswer());
			m.getAnswer().clear();
			for(RR rr : ans) {
				m.addAnswer(rr);
			}
			return m;
		};
	}

	@Test
	public void manyBadSignaturesAreBogusWithoutCheckingThemAll() throws Exception {
		Validator v = validator();
		assertEquals(Validator.Status.SECURE, check(v, "www.sec.test", DNS.A).status);
		long before = Validator.getBudgetExhausted();
		badSignatures(2000);
		Validator.Result r = check(v, "www.sec.test", DNS.A);
		assertEquals(Validator.Status.BOGUS, r.status, r.toString());
		assertTrue(r.why.contains("too many signature checks"), r.why);
		assertEquals(before+1, Validator.getBudgetExhausted());
	}

	@Test
	public void aFewBadSignaturesAreTolerated() throws Exception {
		Validator v = validator();
		badSignatures(3);
		Validator.Result r = check(v, "www.sec.test", DNS.A);
		assertEquals(Validator.Status.SECURE, r.status, "a rollover can leave a signature that doesn't match: "+r);
	}

	@Test
	public void anAnswerOverBudgetDoesntPoisonAnotherZone() throws Exception {
		Validator v = validator();
		//  out.sec.test CNAME www.insecure.test: the CNAME's bad signatures use up the
		//  budget before insecure.test is looked at
		badSignatures("out.sec.test", 2000);
		assertEquals(Validator.Status.BOGUS, check(v, "out.sec.test", DNS.A).status);
		tamper = UnaryOperator.identity();
		Validator.Result r = check(v, "www.insecure.test", DNS.A);
		assertEquals(Validator.Status.INSECURE, r.status, "insecure.test must not be cached as BOGUS: "+r);
		assertEquals(Validator.Status.SECURE, check(v, "www.sec.test", DNS.A).status);
	}

	@Test
	public void theBudgetIsPerValidation() throws Exception {
		Validator v = validator();
		//  many ordinary validations in a row on one thread never run out
		for(int i=0; i < 3*Validator.MAX_VERIFICATIONS; i++ ) {
			v.clear();
			assertEquals(Validator.Status.SECURE, check(v, "www.sec.test", DNS.A).status, "validation "+i);
		}
	}
}
