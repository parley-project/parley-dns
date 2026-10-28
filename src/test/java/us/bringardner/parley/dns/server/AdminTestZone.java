package us.bringardner.parley.dns.server;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * For the admin-port tests: a zone named example and a dynamic file in a temporary directory, so
 * add_dynamic (the command they send to change the server's state, and check it changed or not)
 * works for names like host.example.
 */
final class AdminTestZone implements AutoCloseable {

	private final File dir;
	private final String saved = System.getProperty(DnsServer.PROP_DYNAMIC);

	AdminTestZone(DnsServer server) throws IOException {
		dir = Files.createTempDirectory("admin").toFile();
		System.setProperty(DnsServer.PROP_DYNAMIC, new File(dir, "dynamic.txt").getAbsolutePath());
		File zone = new File(dir, "example.txt");
		Files.write(zone.toPath(), ("@\tIN\tSOA\tns1.example. postmaster.example. ( 1 3600 1800 1209600 300 )\n"
				+"\t\tNS\tns1\nns1\tIN\tA\t10.0.0.53\n").getBytes(StandardCharsets.UTF_8));
		server.addZone(new Zone(zone));
	}

	@Override
	public void close() {
		if( saved == null ) {
			System.clearProperty(DnsServer.PROP_DYNAMIC);
		} else {
			System.setProperty(DnsServer.PROP_DYNAMIC, saved);
		}
		File [] files = dir.listFiles();
		if( files != null ) {
			for(File f : files) {
				f.delete();
			}
		}
		dir.delete();
	}
}
