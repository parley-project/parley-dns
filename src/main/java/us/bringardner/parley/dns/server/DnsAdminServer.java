/**
 * <PRE>
 *
 * Copyright Tony Bringarder 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.SSLContext;

import us.bringardner.parley.net.Connection;
import us.bringardner.parley.net.server.Server;

/**
 * The admin port: parley-net's {@link Server} with a {@link DnsAdminProcessor}
 * per session.
 * <p>
 * The framework does what DnsServer used to do by hand: the accept loop, a
 * thread per session, the session limit (parley.dns.adminMaxConnections, answered
 * "-Too many admin connections"), the idle timeout (parley.dns.adminIdleTimeout), the
 * line length limit (parley.dns.adminMaxLine), the time to log in (parley.dns.adminAuthTimeout)
 * and the delay after a failed login. TLS (parley.dns.adminTls) comes from the server
 * socket factory DnsServer gives it.
 */
public class DnsAdminServer extends Server {

	private final DnsServer dns;
	private volatile int maxLine = DnsAdminProcessor.DEFAULT_MAX_LINE;

	/**
	 * @param dns the DNS server the sessions administer
	 * @param port the admin port (0: any free port)
	 * @param bind the address to listen on (loopback unless parley.dns.adminBindAddress says otherwise)
	 */
	public DnsAdminServer(DnsServer dns, int port, InetAddress bind) {
		super(port, "DnsAdmin");
		setPropertyPrefix("parley.dns.admin");
		this.dns = dns;
		setBindAddr(bind);
		setServerBusyMessage("-Too many admin connections");
		setLoginFailureDelay(1000);
		setMaxClients(8);
		setConnectionFactory(this::connection);
		setProcessorFactory(() -> new DnsAdminProcessor(dns));
	}

	private Connection connection(Socket socket) throws IOException {
		Connection c = new Connection(socket, true) {
			@Override
			public SSLContext getSSLContext(String sslOrTls) throws IOException {
				//  no STARTTLS: TLS from the first byte (parley.dns.adminTls) or none
				return null;
			}
		};
		c.setMaxLineLength(maxLine);
		return c;
	}

	/** @return the longest line a client may send, in bytes (parley.dns.adminMaxLine) */
	public int getMaxLine() {
		return maxLine;
	}

	/** @param maxLine the longest line a client may send; a longer one ends the session */
	public void setMaxLine(int maxLine) {
		this.maxLine = maxLine;
	}

	/** Sessions that can still be opened under {@link #getMaxClients()}. */
	public int getAvailableSlots() {
		int max = getMaxClients();
		return max <= 0 ? Integer.MAX_VALUE : Math.max(0, max-getActiveClients().size());
	}

	/** Only with parley.dns.adminSecret: without one, local clients are logged in from the start. */
	@Override
	protected boolean isLoginRequired() {
		String s = dns.getProperty(DnsServer.PROP_ADMIN_SECRET);
		return s != null && !s.trim().isEmpty();
	}
}
