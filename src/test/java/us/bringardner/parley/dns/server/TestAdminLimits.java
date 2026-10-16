/**
 * <PRE>
 *
 * Copyright Tony Bringarder 1998, 2025 <A href="http://bringardner.com/tony">Tony Bringardner</A>
 *
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       <A href="http://www.apache.org/licenses/LICENSE-2.0">http://www.apache.org/licenses/LICENSE-2.0</A>
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *  </PRE>
 *
 *
 *	@author Tony Bringardner
 */
package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.Name;

/**
 * Admin sessions can't exhaust memory with an endless line, and can't hold a
 * slot for ever without authenticating (rec #36).
 */
public class TestAdminLimits {

	/** A DNS server's admin server (parley-net) on a free port. */
	private static class AdminListener implements AutoCloseable {
		final DnsServer server = new DnsServer();
		final DnsAdminServer admin;
		final String savedSecret = System.getProperty(DnsServer.PROP_ADMIN_SECRET);

		AdminListener(String secret) throws IOException {
			if( secret == null ) {
				System.clearProperty(DnsServer.PROP_ADMIN_SECRET);
			} else {
				System.setProperty(DnsServer.PROP_ADMIN_SECRET, secret);
			}
			admin = server.startAdminServer(0);
		}

		int port() {
			return admin.getLocalPort();
		}

		/** Wait until all admin slots are free again (the session ended). */
		boolean slotsFree(int max, long ms) throws InterruptedException {
			long end = System.currentTimeMillis()+ms;
			while( System.currentTimeMillis() < end ) {
				if( server.getAvailableAdminSlots() == max ) {
					return true;
				}
				Thread.sleep(20);
			}
			return false;
		}

		@Override
		public void close() throws Exception {
			admin.stop();
			if( savedSecret == null ) {
				System.clearProperty(DnsServer.PROP_ADMIN_SECRET);
			} else {
				System.setProperty(DnsServer.PROP_ADMIN_SECRET, savedSecret);
			}
		}
	}

	private static Socket connect(AdminListener l) throws IOException {
		Socket s = new Socket(InetAddress.getLoopbackAddress(), l.port());
		s.setSoTimeout(5000);
		return s;
	}

	private static BufferedReader reader(Socket s) throws IOException {
		return new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
	}

	// ------------------------------------------------------------ line length (parley-net Connection)

	@Test
	public void endlessLineEndsTheSession() throws Exception {
		try(AdminListener l = new AdminListener(null)) {
			//  Count the free slots before connecting: the listener thread takes
			//  one for the session at some point after connect() returns, so a
			//  count read afterwards was sometimes one short and the session's
			//  end (all slots free) never matched it.
			int max = l.server.getAvailableAdminSlots();
			try(Socket s = connect(l)) {
				BufferedReader in = reader(s);
				assertEquals("+JDns admin ready", in.readLine());
				//  Used to be buffered until the heap ran out. Send up to 64 MB without
				//  a line end; the server must close the connection long before that.
				OutputStream out = s.getOutputStream();
				byte [] chunk = new byte[64*1024];
				Arrays.fill(chunk, (byte)'x');
				long sent = 0;
				try {
					while( sent < 64L*1024*1024 ) {
						out.write(chunk);
						sent += chunk.length;
					}
				} catch(IOException expected) {
					//  connection closed by the server
				}
				assertTrue(sent < 64L*1024*1024, "server kept reading: "+sent+" bytes");
				String reply = null;
				try {
					reply = in.readLine();
				} catch(IOException reset) {
					//  the reply can be lost when the connection is reset
				}
				assertTrue(reply == null || reply.startsWith("-Line too long"), reply);
				assertTrue(l.slotsFree(max, 5000), "admin slot released");
			}
		}
	}

	@Test
	public void lineOverTheLimitIsRefused() throws Exception {
		try(AdminListener l = new AdminListener(null)) {
			l.server.setAdminMaxLine(64);
			try(Socket s = connect(l)) {
				BufferedReader in = reader(s);
				assertEquals("+JDns admin ready", in.readLine());
				char [] name = new char[100];
				Arrays.fill(name, 'a');
				s.getOutputStream().write(("add_domain "+new String(name)+".example\r\n").getBytes(StandardCharsets.UTF_8));
				assertEquals("-Line too long (max 64 bytes)", in.readLine());
				assertEquals(null, in.readLine(), "session closed");
			}
			assertTrue(!l.server.isCommon(new Name("www."+"a".repeat(100)+".example")));
		}
	}

	@Test
	public void commandsUnderTheLimitWork() throws Exception {
		try(AdminListener l = new AdminListener(null)) {
			l.server.setAdminMaxLine(64);
			try(Socket s = connect(l)) {
				BufferedReader in = reader(s);
				assertEquals("+JDns admin ready", in.readLine());
				OutputStream out = s.getOutputStream();
				//  Many short lines add up to far more than the limit
				for(int i=0; i < 50; i++ ) {
					out.write(("add_domain d"+i+".example\r\n").getBytes(StandardCharsets.UTF_8));
					assertEquals("+OK", in.readLine());
				}
			}
			assertTrue(l.server.isCommon(new Name("www.d49.example")));
		}
	}

	// ------------------------------------------------------------ auth timeout

	@Test
	public void slowUnauthenticatedClientIsClosed() throws Exception {
		try(AdminListener l = new AdminListener("s3cret")) {
			l.server.setAdminAuthTimeout(500);
			int max = l.server.getAvailableAdminSlots();
			try(Socket s = connect(l)) {
				BufferedReader in = reader(s);
				assertNotNull(AdminAuth.challengeFrom(in.readLine()));
				assertEquals(max-1, l.server.getAvailableAdminSlots());
				//  One byte every 100 ms: never idle, never a whole line
				OutputStream out = s.getOutputStream();
				long start = System.currentTimeMillis();
				boolean closed = false;
				while( !closed && System.currentTimeMillis()-start < 5000 ) {
					try {
						out.write('a');
						out.flush();
					} catch(IOException ex) {
						closed = true;
					}
					if( l.server.getAvailableAdminSlots() == max ) {
						closed = true;
					}
					Thread.sleep(100);
				}
				assertTrue(closed, "session was not closed");
				assertTrue(System.currentTimeMillis()-start < 3000, "closed about when the auth timeout ran out");
			}
			assertTrue(l.slotsFree(max, 5000), "admin slot released");
		}
	}

	@Test
	public void authenticatedSessionOutlivesAuthTimeout() throws Exception {
		try(AdminListener l = new AdminListener("s3cret")) {
			l.server.setAdminAuthTimeout(300);
			DnsAdminClient c = new DnsAdminClient("127.0.0.1", l.port());
			c.setSecret("s3cret");
			c.setTimeout(5000);
			assertTrue(c.connect());
			Thread.sleep(800);
			c.addDomain("late.example");
			c.close();
			assertTrue(l.server.isCommon(new Name("www.late.example")));
		}
	}

	@Test
	public void idleSessionsAreClosedAboutOnTime() throws Exception {
		//  parley-net checks idle sessions every few minutes by default; the admin
		//  server checks often enough to close them about on time
		String saved = System.getProperty(DnsServer.PROP_ADMIN_SECRET);
		System.clearProperty(DnsServer.PROP_ADMIN_SECRET);
		DnsServer server = new DnsServer();
		server.setAdminIdleTimeout(1000);
		DnsAdminServer admin = server.startAdminServer(0);
		try(Socket s = new Socket(InetAddress.getLoopbackAddress(), admin.getLocalPort())) {
			s.setSoTimeout(8000);
			BufferedReader in = reader(s);
			assertEquals("+JDns admin ready", in.readLine());
			long start = System.currentTimeMillis();
			assertEquals(null, in.readLine(), "closed when idle");
			long took = System.currentTimeMillis()-start;
			assertTrue(took < 5000, "closed after "+took+" ms (idle time 1000 ms)");
		} finally {
			admin.stop();
			if( saved != null ) {
				System.setProperty(DnsServer.PROP_ADMIN_SECRET, saved);
			}
		}
	}
}
