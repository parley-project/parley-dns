package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * Round 5 #87 (and round 4 #60): zone reloads, dynamic records and re-signing
 * ran in the admin accept loop, which caught only IOException from a reload.
 * One RuntimeException ended the loop, and with it all reloading and
 * re-signing (signed zones then went bogus when their signatures expired).
 * They now run on their own thread, each step guarded.
 */
public class TestMaintenance {

	@Test
	public void aFailingStepDoesntStopTheOthers() {
		AtomicInteger reloadChecks = new AtomicInteger();
		AtomicInteger signing = new AtomicInteger();
		DnsServer s = new DnsServer() {
			@Override
			boolean shouldReloadZones() {
				reloadChecks.incrementAndGet();
				throw new IllegalStateException("simulated");
			}

			@Override
			void flushDynamicSigning() {
				signing.incrementAndGet();
			}
		};
		//  each round goes on after the failure, and the next round runs too
		s.maintain();
		s.maintain();
		assertEquals(2, reloadChecks.get());
		assertEquals(2, signing.get(), "signing still runs after the reload step failed");
	}

	@Test
	public void maintenanceRunsWhileTheServerRuns() throws Exception {
		AtomicInteger rounds = new AtomicInteger();
		java.io.File dir = java.nio.file.Files.createTempDirectory("maint").toFile();
		try(java.io.FileWriter w = new java.io.FileWriter(new java.io.File(dir, "m.test.txt"))) {
			w.write("@ IN SOA ns1.m.test. postmaster.m.test. ( 1 3600 1800 1209600 300 )\n\tNS ns1\nns1 IN A 10.0.0.53\n");
		}
		java.util.Properties saved = (java.util.Properties) System.getProperties().clone();
		System.setProperty(DnsServer.PROP_DNS_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "m.test");
		System.setProperty(DnsServer.PROP_PORT, "0");
		System.setProperty(DnsServer.PROP_ADMIN_PORT, "0");
		System.setProperty(DnsServer.PROP_UDP_PROC_COUNT, "1");
		System.setProperty(DnsServer.PROP_TCP_PROC_COUNT, "1");
		System.setProperty("parley.dns.resolvers", "1");
		for(String k : new String[] {DnsServer.PROP_USE_DATABASE, DnsServer.PROP_JDBC_URL, DnsServer.PROP_BIND_ADDRESS,
				DnsServer.PROP_UDP_BIND_ADDRESS, DnsServer.PROP_TCP_BIND_ADDRESS, DnsServer.PROP_ADMIN_BIND_ADDRESS,
				DnsServer.PROP_UDP_PORT, DnsServer.PROP_TCP_PORT}) {
			System.clearProperty(k);
		}
		DnsServer.setShutdown(false);
		DnsServer s = new DnsServer() {
			@Override
			boolean shouldReloadZones() {
				rounds.incrementAndGet();
				throw new IllegalStateException("simulated");
			}
		};
		try {
			s.setMaintenancePeriod(100);
			s.start();
			s.awaitStarted(10000);
			long end = System.currentTimeMillis()+5000;
			while( rounds.get() < 3 && System.currentTimeMillis() < end ) {
				Thread.sleep(50);
			}
			assertTrue(rounds.get() >= 3, "maintenance stopped after a failure: "+rounds.get()+" rounds");
		} finally {
			s.stopAndWait(5000);
			DnsServer.setShutdown(false);
			System.setProperties(saved);
			for(java.io.File f : dir.listFiles()) {
				f.delete();
			}
			dir.delete();
		}
	}
}
