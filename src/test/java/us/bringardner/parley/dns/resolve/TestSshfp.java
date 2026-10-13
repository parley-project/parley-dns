package us.bringardner.parley.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.util.Hex;
import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Section;
import us.bringardner.parley.dns.Sshfp;

/**
 * Chunk 8: SSHFP records (RFC 4255, 6594) and checking a host key against them.
 */
public class TestSshfp {

	static final String ED25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f test@host";
	static final String ED25519_SHA256 = "66402c9468c58941dd19ffd650bf2b42f9226f83d3bd06ad515d0e5104a77020";
	static final String ED25519_SHA1 = "568be87a0fbb623a91793addce529ff4c254abd3";
	static final String RSA = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAQQABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj9A";
	static final String RSA_SHA256 = "b3ffc76706c458cf7bce4a6b42cc74e2d00a503f8320ea7aef6aa446c1fbdb54";

	private final Function<Section, Resolver.Answer> saved = SshfpVerifier.resolver;

	@AfterEach
	public void restore() {
		SshfpVerifier.resolver = saved;
	}

	@Test
	public void fingerprintsOfAKey() {
		Sshfp fp = Sshfp.forPublicKeyLine("host.example", ED25519, Sshfp.SHA256);
		assertEquals(Sshfp.ED25519, fp.getAlgorithm());
		assertEquals("4 2 "+ED25519_SHA256, fp.getRdataAsString());
		assertEquals("4 1 "+ED25519_SHA1, Sshfp.forPublicKeyLine("host.example", ED25519, Sshfp.SHA1).getRdataAsString());
		assertEquals("1 2 "+RSA_SHA256, Sshfp.forPublicKeyLine("host.example", RSA, Sshfp.SHA256).getRdataAsString());
		assertEquals(Sshfp.ECDSA, Sshfp.algorithmOf("ecdsa-sha2-nistp384"));
		assertThrows(IllegalArgumentException.class, () -> Sshfp.algorithmOf("ssh-unknown"));
		assertThrows(IllegalArgumentException.class, () -> Sshfp.keyBlob("ssh-rsa "+ED25519.split(" ")[1]), "type mismatch");
		assertThrows(IllegalArgumentException.class, () -> Sshfp.keyBlob("ssh-rsa"));
		assertThrows(IllegalArgumentException.class, () -> Sshfp.keyType(new byte[] {0, 0, 0, 9, 'x'}));
		assertThrows(IllegalArgumentException.class, () -> Sshfp.fingerprint(new byte[1], 3));
	}

	@Test
	public void wireRoundTrip() {
		Sshfp fp = Sshfp.forPublicKeyLine("host.example", ED25519, Sshfp.SHA256);
		fp.setTTL(300);
		Message m = new Message();
		m.setQuestion("host.example", DNS.SSHFP, DNS.IN);
		m.setMessageTypeResponse();
		m.addAnswer(fp);
		Message back = new Message(new ByteBuffer(m.toByteArray()));
		RR rr = back.getAnswer().get(0);
		assertTrue(rr instanceof Sshfp);
		Sshfp b = (Sshfp)rr;
		assertEquals(Sshfp.ED25519, b.getAlgorithm());
		assertEquals(Sshfp.SHA256, b.getFingerprintType());
		assertArrayEquals(Hex.decode(ED25519_SHA256), b.getFingerprint());
		assertTrue(b.matches(Sshfp.keyBlob(ED25519)));
		assertFalse(b.matches(Sshfp.keyBlob(RSA)));
		assertTrue(b.copy() instanceof Sshfp);
		assertTrue(b.toString().contains(ED25519_SHA256));
		assertThrows(IllegalArgumentException.class, () -> b.setAlgorithm(256));
		assertThrows(IllegalArgumentException.class, () -> b.setFingerprintType(-1));
	}

	@Test
	public void inAZoneFile() throws Exception {
		File dir = Files.createTempDirectory("sshfp").toFile();
		File zone = new File(dir, "sshfp.test.txt");
		try {
			try(FileWriter w = new FileWriter(zone)) {
				w.write("@\tIN\tSOA\tns1.sshfp.test. postmaster.sshfp.test. ( 1 3600 1800 1209600 300 )\n"
						+"\t\tNS\tns1\n"
						+"ns1\tIN\tA\t10.0.0.53\n"
						+"host\tIN\tSSHFP\t4 2 "+ED25519_SHA256.substring(0, 32)+" "+ED25519_SHA256.substring(32)+"\n");
			}
			us.bringardner.parley.dns.server.Zone z = new us.bringardner.parley.dns.server.Zone(zone);
			boolean found = false;
			for(RR rr : z.getMatchingRRs("host.sshfp.test")) {
				if( rr instanceof Sshfp ) {
					found = true;
					assertEquals("4 2 "+ED25519_SHA256, rr.getRdataAsString());
				}
			}
			assertTrue(found);
			assertTrue(us.bringardner.parley.dns.server.Zone.isUpdatableType(DNS.SSHFP));
		} finally {
			zone.delete();
			dir.delete();
		}
	}

	// ------------------------------------------------------------ verifier

	private static Message answer(String host, Sshfp ... records) {
		Message m = new Message();
		m.setQuestion(host, DNS.SSHFP, DNS.IN);
		m.setMessageTypeResponse();
		for(Sshfp r : records) {
			m.addAnswer(r);
		}
		return m;
	}

	private static Validator.Result secure(Message m) {
		Set<String> keys = new HashSet<String>();
		for(RR rr : m.getAnswer()) {
			keys.add(Validator.recordKey('A', rr));
		}
		return new Validator.Result(Validator.Status.SECURE, null, keys);
	}

	private static void answers(Message m, Validator.Result r) {
		SshfpVerifier.resolver = q -> new Resolver.Answer(m, r);
	}

	@Test
	public void aValidatedMatchingRecordIsAMatch() {
		Message m = answer("host.example", Sshfp.forPublicKeyLine("host.example", RSA, Sshfp.SHA256),
				Sshfp.forPublicKeyLine("host.example", ED25519, Sshfp.SHA256));
		answers(m, secure(m));
		assertEquals(SshfpVerifier.Result.MATCH, SshfpVerifier.verify("host.example", ED25519));
	}

	@Test
	public void aDifferentKeyOfTheSameTypeIsAMismatch() {
		Sshfp other = Sshfp.forPublicKeyLine("host.example", ED25519, Sshfp.SHA256);
		other.setFingerprint(new byte[32]);
		Message m = answer("host.example", other);
		answers(m, secure(m));
		assertEquals(SshfpVerifier.Result.MISMATCH, SshfpVerifier.verify("host.example", ED25519));
	}

	@Test
	public void recordsForOtherKeyTypesOnlyAreNoRecords() {
		Message m = answer("host.example", Sshfp.forPublicKeyLine("host.example", RSA, Sshfp.SHA256));
		answers(m, secure(m));
		assertEquals(SshfpVerifier.Result.NO_RECORDS, SshfpVerifier.verify("host.example", ED25519));
		Message none = answer("host.example");
		answers(none, secure(none));
		assertEquals(SshfpVerifier.Result.NO_RECORDS, SshfpVerifier.verify("host.example", ED25519));
	}

	@Test
	public void onlyValidatedRecordsCount() {
		Message m = answer("host.example", Sshfp.forPublicKeyLine("host.example", ED25519, Sshfp.SHA256));
		//  SECURE, but this record wasn't among those checked (round 5 #83)
		answers(m, new Validator.Result(Validator.Status.SECURE, null, new HashSet<String>()));
		assertEquals(SshfpVerifier.Result.NO_RECORDS, SshfpVerifier.verify("host.example", ED25519));
	}

	@Test
	public void unvalidatedAnswersProveNothing() {
		Message m = answer("host.example", Sshfp.forPublicKeyLine("host.example", ED25519, Sshfp.SHA256));
		answers(m, null);
		assertEquals(SshfpVerifier.Result.INSECURE, SshfpVerifier.verify("host.example", ED25519), "validation off");
		answers(m, new Validator.Result(Validator.Status.INSECURE, "unsigned"));
		assertEquals(SshfpVerifier.Result.INSECURE, SshfpVerifier.verify("host.example", ED25519));
		answers(m, new Validator.Result(Validator.Status.BOGUS, "bad signature"));
		assertEquals(SshfpVerifier.Result.BOGUS, SshfpVerifier.verify("host.example", ED25519));
		answers(null, new Validator.Result(Validator.Status.BOGUS, "bad signature"));
		assertEquals(SshfpVerifier.Result.BOGUS, SshfpVerifier.verify("host.example", ED25519));
	}

	@Test
	public void noAnswerIsATemporaryFailure() {
		answers(null, null);
		assertEquals(SshfpVerifier.Result.TEMPFAIL, SshfpVerifier.verify("host.example", ED25519));
		SshfpVerifier.resolver = q -> null;
		assertEquals(SshfpVerifier.Result.TEMPFAIL, SshfpVerifier.verify("host.example", ED25519));
		SshfpVerifier.resolver = q -> { throw new IllegalStateException("down"); };
		assertEquals(SshfpVerifier.Result.TEMPFAIL, SshfpVerifier.verify("host.example", ED25519));
		Message fail = answer("host.example");
		fail.setResponseCode(DNS.SERVER_ERROR);
		answers(fail, secure(fail));
		assertEquals(SshfpVerifier.Result.TEMPFAIL, SshfpVerifier.verify("host.example", ED25519));
	}

	@Test
	public void aKeyTypeWithoutAnAlgorithmHasNoRecords() {
		byte [] odd = {0, 0, 0, 7, 's', 's', 'h', '-', 'x', 'y', 'z'};
		assertEquals(SshfpVerifier.Result.NO_RECORDS, SshfpVerifier.verify("host.example", odd));
	}

	// ------------------------------------------------------------ tool

	@Test
	public void theToolPrintsRecords() throws Exception {
		File f = File.createTempFile("host", ".pub");
		try {
			Files.write(f.toPath(), (ED25519+"\n# comment\n\n"+RSA+"\n").getBytes());
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			ByteArrayOutputStream err = new ByteArrayOutputStream();
			int rc = us.bringardner.parley.dns.util.SshfpToolAccess.run(new String[] {"-sha1", "host.example", f.getPath()},
					new PrintStream(out), new PrintStream(err));
			assertEquals(0, rc, err.toString());
			String text = out.toString();
			assertTrue(text.contains("host.example. IN SSHFP 4 2 "+ED25519_SHA256), text);
			assertTrue(text.contains("host.example. IN SSHFP 4 1 "+ED25519_SHA1), text);
			assertTrue(text.contains("host.example. IN SSHFP 1 2 "+RSA_SHA256), text);
			assertEquals(2, us.bringardner.parley.dns.util.SshfpToolAccess.run(new String[0], new PrintStream(out), new PrintStream(err)));
			Files.write(f.toPath(), "garbage line\n".getBytes());
			assertEquals(1, us.bringardner.parley.dns.util.SshfpToolAccess.run(new String[] {"h", f.getPath()}, new PrintStream(out), new PrintStream(err)));
		} finally {
			f.delete();
		}
	}

	private static byte [] sshString(byte [] b) {
		byte [] r = new byte[4+b.length];
		r[0] = (byte)(b.length >> 24);
		r[1] = (byte)(b.length >> 16);
		r[2] = (byte)(b.length >> 8);
		r[3] = (byte)b.length;
		System.arraycopy(b, 0, r, 4, b.length);
		return r;
	}

	@Test
	public void aCertificateIsCheckedByItsKey() throws Exception {
		byte [] plain = Sshfp.keyBlob(ED25519);
		byte [] pk = java.util.Arrays.copyOfRange(plain, plain.length-36, plain.length);	//  the pk string
		ByteArrayOutputStream cert = new ByteArrayOutputStream();
		cert.write(sshString("ssh-ed25519-cert-v01@openssh.com".getBytes()));
		cert.write(sshString(new byte[32]));		//  nonce
		cert.write(pk);
		cert.write(new byte[] {0, 0, 0, 0, 0, 0, 0, 1});	//  serial, and the rest of a certificate
		cert.write(sshString("host.example".getBytes()));
		byte [] c = cert.toByteArray();
		assertArrayEquals(plain, Sshfp.plainKey(c));
		Message m = answer("host.example", Sshfp.forPublicKeyLine("host.example", ED25519, Sshfp.SHA256));
		answers(m, secure(m));
		assertEquals(SshfpVerifier.Result.MATCH, SshfpVerifier.verify("host.example", c));
		assertThrows(IllegalArgumentException.class, () -> Sshfp.plainKey(java.util.Arrays.copyOf(c, 50)), "truncated");
		assertArrayEquals(plain, Sshfp.plainKey(plain), "a plain key as it is");
	}

	@Test
	public void recordsOfUnknownFingerprintTypesAreIgnored() {
		Sshfp future = new Sshfp("host.example");
		future.setAlgorithm(Sshfp.ED25519);
		future.setFingerprintType(3);
		future.setFingerprint(new byte[48]);
		Sshfp shortOne = new Sshfp("host.example");
		shortOne.setAlgorithm(Sshfp.ED25519);
		shortOne.setFingerprintType(Sshfp.SHA256);
		shortOne.setFingerprint(new byte[8]);
		assertFalse(future.isUsable());
		assertFalse(shortOne.isUsable());
		Message m = answer("host.example", future, shortOne);
		answers(m, secure(m));
		assertEquals(SshfpVerifier.Result.NO_RECORDS, SshfpVerifier.verify("host.example", ED25519), "not a mismatch");
	}

	@Test
	public void theToolReportsBadInput() throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ByteArrayOutputStream err = new ByteArrayOutputStream();
		PrintStream o = new PrintStream(out);
		PrintStream e = new PrintStream(err);
		assertEquals(2, us.bringardner.parley.dns.util.SshfpToolAccess.run(new String[] {"-sha256", "h"}, o, e));
		assertEquals(1, us.bringardner.parley.dns.util.SshfpToolAccess.run(new String[] {"h", "/nonexistent/key.pub"}, o, e));
		File f = File.createTempFile("host", ".pub");
		try {
			Files.write(f.toPath(), (ED25519.replace("test@host", "root@h\u00f6st")+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
			assertEquals(0, us.bringardner.parley.dns.util.SshfpToolAccess.run(new String[] {"h", f.getPath()}, o, e), "a non-ASCII comment");
		} finally {
			f.delete();
		}
	}
}
