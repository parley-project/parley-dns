package us.bringardner.parley.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.util.Hex;
import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Dnskey;
import us.bringardner.parley.dns.Ds;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Rrsig;
import us.bringardner.parley.dns.Section;
import us.bringardner.parley.dns.dnssec.Algorithm;
import us.bringardner.parley.dns.dnssec.Canonical;
import us.bringardner.parley.dns.dnssec.DnssecKey;

/**
 * Round 5 #89 (SHA-1 DS ignored next to SHA-256) and #90 (revoked keys).
 */
public class TestValidatorKeyRules {

	private static final String ZONE = "rules.example";
	private final long now = System.currentTimeMillis()/1000;

	private Message signed(Section q, List<RR> rrset, DnssecKey k) {
		Message m = new Message();
		m.setQuestion(q.getName(), q.getType(), DNS.IN);
		m.setMessageTypeResponse();
		for(RR rr : rrset) {
			m.addAnswer(rr);
		}
		Rrsig sig = Canonical.sign(q.getName(), rrset, 3600, k, now-3600, now+86400);
		sig.setKeyTag(tag);
		//  signed again with the key tag set (it is part of the signed data)
		sig.setSignature(k.sign(Canonical.signedData(sig, q.getName(), rrset)));
		m.addAnswer(sig);
		return m;
	}

	//  the key tag the RRSIGs carry (a revoked key has another one)
	private int tag;

	private Validator.Status check(DnssecKey k, String anchors) {
		return check(k, anchors, k.getDnskey());
	}

	/** @param dk the DNSKEY record served for k (e.g. with the REVOKE bit) */
	private Validator.Status check(DnssecKey k, String anchors, Dnskey dk) {
		dk.setTTL(3600);
		tag = dk.getKeyTag();
		Message keys = signed(new Section(ZONE, DNS.DNSKEY, DNS.IN), Collections.<RR>singletonList(dk), k);
		Validator v = new Validator(q -> q.getType() == DNS.DNSKEY && Canonical.key(q.getName()).equals(ZONE) ? keys : null,
				() -> now, Validator.parseAnchors(anchors), 100);
		A a = new A(ZONE);
		a.setAddress("10.9.9.9");
		a.setTTL(3600);
		Section q = new Section(ZONE, DNS.A, DNS.IN);
		List<RR> set = new ArrayList<RR>();
		set.add(a);
		return v.validate(signed(q, set, k), q).status;
	}

	private static String sha1Ds(DnssecKey k) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(Canonical.nameWire(ZONE));
		md.update(k.getDnskey().rdataBytes());
		return ZONE+". IN DS "+k.getKeyTag()+" "+k.getAlgorithm()+" 1 "+Hex.encode(md.digest());
	}

	private static String sha256Ds(DnssecKey k) {
		Ds ds = k.toDs(Ds.SHA256, 0);
		return ZONE+". IN DS "+ds.getRdataAsString();
	}

	private static DnssecKey key() throws Exception {
		return DnssecKey.generate(ZONE, Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
	}

	@Test
	public void theSetupValidates() throws Exception {
		DnssecKey k = key();
		assertEquals(Validator.Status.SECURE, check(k, sha256Ds(k)));
		assertEquals(Validator.Status.SECURE, check(k, sha1Ds(k)), "SHA-1 alone is still used");
	}

	@Test
	public void sha1IsIgnoredNextToSha256() throws Exception {
		DnssecKey k = key();
		String wrong256 = ZONE+". IN DS "+k.getKeyTag()+" "+k.getAlgorithm()+" 2 "+Hex.encode(new byte[32]);
		//  a matching SHA-1 DS must not rescue a SHA-256 DS that doesn't match (RFC 4509 3)
		assertEquals(Validator.Status.BOGUS, check(k, sha1Ds(k)+"\n"+wrong256));
		assertEquals(Validator.Status.SECURE, check(k, sha1Ds(k)+"\n"+sha256Ds(k)));
	}

	@Test
	public void aRevokedKeyValidatesNothing() throws Exception {
		DnssecKey k = key();
		Dnskey revoked = k.getDnskey();
		revoked.setFlags(revoked.getFlags() | Dnskey.FLAG_REVOKE);
		//  the DS and the signatures all point at the revoked key: consistent, but it may not be used
		Ds ds = DnssecKey.ds(ZONE, revoked, Ds.SHA256, 0);
		String anchor = ZONE+". IN DS "+ds.getRdataAsString();
		assertEquals(Validator.Status.BOGUS, check(k, anchor, revoked));
		//  the same with the bit clear validates (so it is the bit that counts)
		assertEquals(Validator.Status.SECURE, check(k, sha256Ds(k), k.getDnskey()));
	}
}
