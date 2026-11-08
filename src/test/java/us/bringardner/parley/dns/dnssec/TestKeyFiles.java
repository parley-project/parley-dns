package us.bringardner.parley.dns.dnssec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import us.bringardner.parley.dns.TestFiles;
import us.bringardner.parley.files.FileSource;

/**
 * Chunk 5: key files (round 5 #94) and ECDSA keys checked with parley-core's Ec. The key files
 * are FileSources: each test runs on the local and the memory file system.
 */
public class TestKeyFiles {

	@TempDir
	Path tmp;

	private FileSource dir(String fs) throws IOException {
		return TestFiles.folder(fs, tmp);
	}

	@ParameterizedTest
	@ValueSource(strings = {TestFiles.LOCAL, TestFiles.MEMORY})
	public void aPrivateFileIsOnlyReadableByItsOwner(String fs) throws Exception {
		FileSource dir = dir(fs);
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		k.save(dir);
		FileSource priv = dir.getChild(k.baseName()+".private");
		Assumptions.assumeTrue(priv.canOwnerRead() || priv.canGroupRead() || priv.canOtherRead(), "no permissions");
		assertTrue(priv.canOwnerRead());
		assertTrue(priv.canOwnerWrite());
		assertFalse(priv.canOwnerExecute());
		assertFalse(priv.canGroupRead());
		assertFalse(priv.canGroupWrite());
		assertFalse(priv.canGroupExecute());
		assertFalse(priv.canOtherRead());
		assertFalse(priv.canOtherWrite());
		assertFalse(priv.canOtherExecute());
		DnssecKey back = DnssecKey.load(dir.getChild(k.baseName()+".key"));
		assertEquals(k.getKeyTag(), back.getKeyTag());
		assertTrue(back.hasPrivateKey());
		assertEquals(dir.getChild(k.baseName()+".key"), back.getKeyFile());
	}

	@ParameterizedTest
	@ValueSource(strings = {TestFiles.LOCAL, TestFiles.MEMORY})
	public void aSymlinkWhereThePrivateFileGoesIsRefused(String fs) throws Exception {
		FileSource dir = dir(fs);
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		FileSource target = dir.getChild("elsewhere");
		FileSource priv = dir.getChild(k.baseName()+".private");
		try {
			dir.getFileSourceFactory().createSymbolicLink(priv, target);
		} catch(UnsupportedOperationException | IOException ex) {
			Assumptions.assumeTrue(false, "no symlinks: "+ex);
		}
		assertThrows(IOException.class, () -> k.save(dir));
		assertFalse(target.exists(), "nothing written through the link");
		assertFalse(dir.getChild(k.baseName()+".key").exists(), "no .key written");
	}

	@ParameterizedTest
	@ValueSource(strings = {TestFiles.LOCAL, TestFiles.MEMORY})
	public void aKeySavedTwiceIsRefused(String fs) throws Exception {
		FileSource dir = dir(fs);
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		k.save(dir);
		String before = TestFiles.read(dir.getChild(k.baseName()+".private"));
		assertThrows(IOException.class, () -> k.save(dir));
		assertEquals(before, TestFiles.read(dir.getChild(k.baseName()+".private")), "the first one is kept");
	}

	@ParameterizedTest
	@ValueSource(strings = {TestFiles.LOCAL, TestFiles.MEMORY})
	public void aPrivateKeyThatDoesntMatchItsKeyFileIsRefused(String fs) throws Exception {
		FileSource dir = dir(fs);
		DnssecKey a = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		DnssecKey b = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		a.save(dir);
		FileSource other = TestFiles.mkdir(dir, "other");
		b.save(other);
		//  a's .key with b's .private
		FileSource priv = dir.getChild(a.baseName()+".private");
		assertTrue(priv.delete());
		TestFiles.copy(other.getChild(b.baseName()+".private"), priv);
		assertThrows(IOException.class, () -> DnssecKey.load(dir.getChild(a.baseName()+".key")));
	}

	@ParameterizedTest
	@ValueSource(strings = {TestFiles.LOCAL, TestFiles.MEMORY})
	public void anExposedPrivateFileStillLoads(String fs) throws Exception {
		FileSource dir = dir(fs);
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		k.save(dir);
		FileSource priv = dir.getChild(k.baseName()+".private");
		priv.setGroupReadable(true);
		priv.setOtherReadable(true);
		Assumptions.assumeTrue(priv.canOtherRead(), "no permissions");
		//  a warning is logged; the server keeps signing
		assertEquals(k.getKeyTag(), DnssecKey.load(dir.getChild(k.baseName()+".key")).getKeyTag());
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

	@ParameterizedTest
	@ValueSource(strings = {TestFiles.LOCAL, TestFiles.MEMORY})
	public void aSymlinkWhereTheKeyFileGoesIsRefused(String fs) throws Exception {
		FileSource dir = dir(fs);
		DnssecKey k = DnssecKey.generate("files.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		FileSource target = dir.getChild("elsewhere");
		FileSource key = dir.getChild(k.baseName()+".key");
		try {
			dir.getFileSourceFactory().createSymbolicLink(key, target);
		} catch(UnsupportedOperationException | IOException ex) {
			Assumptions.assumeTrue(false, "no symlinks: "+ex);
		}
		assertThrows(IOException.class, () -> k.save(dir));
		assertFalse(target.exists(), "nothing written through the link");
		assertFalse(dir.getChild(k.baseName()+".private").exists(), "no .private left behind");
	}

	@ParameterizedTest
	@ValueSource(strings = {TestFiles.LOCAL, TestFiles.MEMORY})
	public void loadDirFindsTheKeysAndTheStampFollowsThem(String fs) throws Exception {
		FileSource dir = dir(fs);
		assertEquals(0, DnssecKey.dirStamp(dir.getChild("missing")));
		assertTrue(DnssecKey.loadDir(dir.getChild("missing"), new java.util.ArrayList<String>()).isEmpty());
		long empty = DnssecKey.dirStamp(dir);
		DnssecKey k = DnssecKey.generate("dir.test", Algorithm.of(Algorithm.ECDSAP256SHA256), true, 0);
		k.save(dir);
		long one = DnssecKey.dirStamp(dir);
		assertTrue(one != empty);
		TestFiles.write(dir.getChild("Kbroken.test.+013+00001.key"), "not a key\n");
		java.util.List<String> errors = new java.util.ArrayList<String>();
		java.util.Map<String, java.util.List<DnssecKey>> all = DnssecKey.loadDir(dir, errors);
		assertEquals(1, all.get("dir.test").size());
		assertEquals(k.getKeyTag(), all.get("dir.test").get(0).getKeyTag());
		assertEquals(1, errors.size(), errors.toString());
		assertTrue(DnssecKey.dirStamp(dir) != one);
	}
}
