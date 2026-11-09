package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.TestFiles;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;

/**
 * {@link TestListedDomains} with the files on a memory file system (To-Do 18.15): the server reads them
 * through filesource: URLs.
 */
public class TestListedDomainsOnMemory extends TestListedDomains {

	@Override
	protected FileSource folder(String prefix) throws IOException {
		return TestFiles.newFolder(TestFiles.folder(TestFiles.MEMORY, null), prefix);
	}

	@Test
	public void theZoneFolderIsOnTheMemoryFileSystem() throws Exception {
		assertTrue(dir.getFileSourceFactory() instanceof MemoryFileSourceFactory);
		assertEquals(dir.getCanonicalPath(), server.getZoneDirectory().getCanonicalPath());
		assertTrue(server.getZoneDirectory().getFileSourceFactory() instanceof MemoryFileSourceFactory);
	}
}
