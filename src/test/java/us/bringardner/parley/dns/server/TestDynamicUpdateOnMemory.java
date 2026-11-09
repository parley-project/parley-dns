package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.TestFiles;
import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;

/**
 * {@link TestDynamicUpdate} with the files on a memory file system (To-Do 18.15): the server reads them
 * through filesource: URLs.
 */
public class TestDynamicUpdateOnMemory extends TestDynamicUpdate {

	@Override
	protected FileSource folder(String prefix) throws IOException {
		return TestFiles.newFolder(TestFiles.folder(TestFiles.MEMORY, null), prefix);
	}

	@Test
	public void theZonesAndJournalsAreOnTheMemoryFileSystem() throws Exception {
		assertTrue(server.getZoneDirectory().getFileSourceFactory() instanceof MemoryFileSourceFactory);
		assertTrue(server.getZone("up.test").getJournalFile().getFileSourceFactory() instanceof MemoryFileSourceFactory);
	}
}
