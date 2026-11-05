package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.net.ServerSocket;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import us.bringardner.parley.net.server.KnownSettings;

/**
 * To-Do 2.16: parley-dns's list of settings (META-INF/parley/settings.list) has every name its code
 * spells out, and every name the DNS server reads while it starts (from its own configuration, as
 * its provider gives it), so a server's start-up check never warns about a real setting.
 */
public class TestKnownSettings {

	@TempDir
	File dir;

	@Test
	public void everyConstantIsListed() throws Exception {
		assertEquals(List.of(), KnownSettings.load().undeclared(KnownSettings.settingConstants(DnsServer.class)));
	}


	@SuppressWarnings("unused")
	private static int freePort() throws Exception {
		try (ServerSocket s = new ServerSocket(0)) {
			return s.getLocalPort();
		}
	}
}
