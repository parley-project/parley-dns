package us.bringardner.parley.dns;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import us.bringardner.parley.files.FileSource;

/**
 * Test fixtures (zone files, nslookup / nsupdate scripts, keys) live in src/test/resources and are
 * found on the test class path, so the tests don't depend on the working directory or on where the
 * build puts its output. They are FileSources on the local file system.
 */
public final class Fixtures {

	private Fixtures() {
	}

	/**
	 * The project folder (the one with pom.xml), for tests that check the sources or README.md.
	 * Found by walking up from where the test classes are, so it works from any working directory
	 * and whatever the build's output folder is called.
	 * @return the project folder
	 * @throws IllegalStateException if there is no pom.xml above the test classes
	 */
	public static FileSource projectDir() {
		FileSource dir;
		try {
			dir = FileSource.of(Fixtures.class.getProtectionDomain().getCodeSource().getLocation().toURI());
			for(FileSource d = dir; d != null; d = d.getParentFile()) {
				if( d.getChild("pom.xml").isFile() ) {
					return d;
				}
			}
		} catch(URISyntaxException | IOException e) {
			throw new IllegalStateException(e);
		}
		throw new IllegalStateException("no pom.xml above "+dir);
	}

	/**
	 * @param path a path relative to src/test/resources, e.g. "TestFiles/zones/foo.com.txt"
	 * @return the fixture as a file
	 * @throws IllegalStateException if it is not on the test class path
	 */
	public static FileSource file(String path) {
		URL url = Fixtures.class.getResource("/"+path);
		if( url == null ) {
			throw new IllegalStateException(path+" is not on the test class path (src/test/resources)");
		}
		try {
			return FileSource.of(url.toURI());
		} catch(URISyntaxException | IOException e) {
			throw new IllegalStateException(url.toString(), e);
		}
	}

}
