package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.dns.TestFiles;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;

/**
 * To-Do 18.15: the server's file system (parley.dns.fileSource) and the files its settings name.
 */
public class TestDnsFiles {

	@TempDir
	Path tmp;

	@Test
	public void withoutTheSettingItIsTheDefaultFileSystem() throws Exception {
		assertSame(FileSourceFactory.getDefaultFactory(), DnsFiles.factory(new Properties()));
		assertSame(FileSourceFactory.getDefaultFactory(), DnsFiles.factory(" ", null));
		DnsServer server = new DnsServer();
		server.setConfiguration(new Properties());
		assertSame(FileSourceFactory.getDefaultFactory(), server.getFileSourceFactory());
	}

	@Test
	public void theSettingNamesTheFileSystemAndTheServerMakesItOnce() throws Exception {
		Properties p = new Properties();
		p.setProperty(DnsServer.PROP_FILE_SOURCE, "Memory");
		FileSourceFactory f = DnsFiles.factory(p);
		assertTrue(f instanceof MemoryFileSourceFactory);
		assertTrue(f.isConnected());
		assertNotSame(f, DnsFiles.factory(p), "a new one each time");
		DnsServer server = new DnsServer();
		server.setConfiguration(p);
		FileSourceFactory mine = server.getFileSourceFactory();
		assertTrue(mine instanceof MemoryFileSourceFactory);
		assertSame(mine, server.getFileSourceFactory(), "one per server");
		assertNotSame(FileSourceFactory.getDefaultFactory(), mine);
	}

	@Test
	public void anUnknownFileSystemIsNamed() {
		Properties p = new Properties();
		p.setProperty(DnsServer.PROP_FILE_SOURCE, "nosuch");
		IOException e = assertThrows(IOException.class, () -> DnsFiles.factory(p));
		assertTrue(e.getMessage().contains("nosuch") && e.getMessage().contains(DnsServer.PROP_FILE_SOURCE), e.getMessage());
	}

	@Test
	public void theConnectionSettingsAreUnderThePrefix() {
		Properties p = new Properties();
		p.setProperty(DnsServer.PROP_FILE_SOURCE, "sftp");
		p.setProperty(DnsServer.PROP_FILE_SOURCE+".host", " dns.example ");
		p.setProperty(DnsServer.PROP_FILE_SOURCE+".", "nothing");
		p.setProperty("parley.dns.fileSourceX", "other");
		Properties c = DnsFiles.connectionSettings(p, DnsServer.PROP_FILE_SOURCE+".");
		assertEquals(1, c.size(), c.toString());
		assertEquals("dns.example", c.getProperty("host"));
	}

	@Test
	public void aRelativePathIsUnderTheFolder() throws Exception {
		FileSource dir = TestFiles.local(tmp);
		FileSourceFactory local = dir.getFileSourceFactory();
		assertEquals(dir.getChild("keys/tsig.txt"), DnsFiles.resolve(local, dir, " keys/tsig.txt "));
		FileSource abs = DnsFiles.resolve(local, dir, dir.getChild("x").getAbsolutePath());
		assertEquals(dir.getChild("x").getAbsolutePath(), abs.getAbsolutePath());
		assertTrue(DnsFiles.isAbsolutePath("/etc/parley"));
		assertFalse(DnsFiles.isAbsolutePath("zones"));
		assertFalse(DnsFiles.isAbsolutePath("filesource:/zones?sourcetype=memory"), "a URL isn't a path");
	}

	@Test
	public void aUrlIsItsOwnFileSystem() throws Exception {
		FileSource memory = TestFiles.folder(TestFiles.MEMORY, tmp);
		TestFiles.write(memory.getChild("tsig.txt"), "k hmac-sha256 c2VjcmV0\n");
		FileSource dir = TestFiles.local(tmp);
		FileSource f = DnsFiles.resolve(dir.getFileSourceFactory(), dir, TestFiles.setting(memory.getChild("tsig.txt")));
		assertTrue(f.getFileSourceFactory() instanceof MemoryFileSourceFactory);
		assertTrue(f.exists());
		assertEquals("k hmac-sha256 c2VjcmV0\n", TestFiles.read(f));
	}
}
