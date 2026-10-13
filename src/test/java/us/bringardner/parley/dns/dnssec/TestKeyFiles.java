package us.bringardner.parley.dns.dnssec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Chunk 5: key files (round 5 #94) and ECDSA keys checked with parley-core's Ec.
 */
public class TestKeyFiles {

	private File dir;

	@BeforeEach
	public void setup() throws IOException {
		dir = Files.createTempDirectory("keyfiles").toFile();
	}

	@AfterEach
	public void cleanup() {
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	@Test
	public void aPrivateFileIsOnlyReadableByItsOwner() throws Exception {
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		k.save(dir);
		File priv = new File(dir, k.baseName()+".private");
		try {
			assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(priv.toPath())));
		} catch(UnsupportedOperationException ex) {
			Assumptions.assumeTrue(false, "no POSIX permissions");
		}
		DnssecKey back = DnssecKey.load(new File(dir, k.baseName()+".key"));
		assertEquals(k.getKeyTag(), back.getKeyTag());
	}

	@Test
	public void aSymlinkWhereThePrivateFileGoesIsRefused() throws Exception {
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		File target = new File(dir, "elsewhere");
		File priv = new File(dir, k.baseName()+".private");
		try {
			Files.createSymbolicLink(priv.toPath(), target.toPath());
		} catch(UnsupportedOperationException | IOException ex) {
			Assumptions.assumeTrue(false, "no symlinks: "+ex);
		}
		assertThrows(IOException.class, () -> k.save(dir));
		assertFalse(target.exists(), "nothing written through the link");
	}

	@Test
	public void aPrivateKeyThatDoesntMatchItsKeyFileIsRefused() throws Exception {
		DnssecKey a = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		DnssecKey b = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		a.save(dir);
		File other = Files.createTempDirectory("keyfiles2").toFile();
		try {
			b.save(other);
			//  a's .key with b's .private
			File priv = new File(dir, a.baseName()+".private");
			priv.delete();
			Files.copy(new File(other, b.baseName()+".private").toPath(), priv.toPath());
			assertThrows(IOException.class, () -> DnssecKey.load(new File(dir, a.baseName()+".key")));
		} finally {
			for(File f : other.listFiles()) {
				f.delete();
			}
			other.delete();
		}
	}

	@Test
	public void anExposedPrivateFileStillLoads() throws Exception {
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		k.save(dir);
		File priv = new File(dir, k.baseName()+".private");
		try {
			Files.setPosixFilePermissions(priv.toPath(), PosixFilePermissions.fromString("rw-r--r--"));
		} catch(UnsupportedOperationException ex) {
			Assumptions.assumeTrue(false, "no POSIX permissions");
		}
		//  a warning is logged; the server keeps signing
		assertEquals(k.getKeyTag(), DnssecKey.load(new File(dir, k.baseName()+".key")).getKeyTag());
	}

	@Test
	public void anEcdsaKeyOffTheCurveVerifiesNothing() throws Exception {
		Algorithm alg = Algorithm.of(Algorithm.ECDSAP256SHA256);
		KeyPair kp = alg.generate(0);
		byte [] field = alg.publicKeyField(kp.getPublic());
		byte [] data = "data".getBytes(StandardCharsets.US_ASCII);
		byte [] sig = alg.sign(kp.getPrivate(), data);
		assertEquals(64, sig.length);
		assertTrue(alg.verify(field, data, sig));
		byte [] bad = field.clone();
		bad[63] ^= 1;
		assertFalse(alg.verify(bad, data, sig), "not a point on the curve");
		assertFalse(alg.verify(field, data, new byte[64]), "r = s = 0");
		assertFalse(alg.verify(field, data, new byte[63]));
	}

	@Test
	public void p384SignaturesAreFixedSize() throws Exception {
		Algorithm alg = Algorithm.of(Algorithm.ECDSAP384SHA384);
		KeyPair kp = alg.generate(0);
		byte [] data = {1, 2, 3};
		for(int i=0; i < 20; i++ ) {
			byte [] sig = alg.sign(kp.getPrivate(), data);
			assertEquals(96, sig.length);
			assertTrue(alg.verify(alg.publicKeyField(kp.getPublic()), data, sig));
		}
		assertArrayEquals(alg.publicKeyField(kp.getPublic()), alg.publicKeyField(kp.getPublic()));
	}

	@Test
	public void aSymlinkWhereTheKeyFileGoesIsRefused() throws Exception {
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		File target = new File(dir, "elsewhere");
		File key = new File(dir, k.baseName()+".key");
		try {
			Files.createSymbolicLink(key.toPath(), target.toPath());
		} catch(UnsupportedOperationException | IOException ex) {
			Assumptions.assumeTrue(false, "no symlinks: "+ex);
		}
		assertThrows(IOException.class, () -> k.save(dir));
		assertFalse(target.exists(), "nothing written through the link");
		assertFalse(new File(dir, k.baseName()+".private").exists(), "no .private left behind");
	}
}
