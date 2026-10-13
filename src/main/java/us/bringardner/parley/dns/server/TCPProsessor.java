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
 *
 *
 * ~version~V000.00.05-V000.00.00-
 */
package us.bringardner.parley.dns.server;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import us.bringardner.parley.core.NamedThreadFactory;
import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DnsFormatException;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Tsig;
import us.bringardner.parley.dns.Utility;
import us.bringardner.parley.dns.resolve.QueryData;
import us.bringardner.parley.io.IoUtils;
import us.bringardner.parley.net.nio.INioConnection;
import us.bringardner.parley.net.nio.INioHandler;
import us.bringardner.parley.net.nio.LengthFieldFrameDecoder;
import us.bringardner.parley.net.nio.NioServer;

/**
 * DNS over TCP (RFC 1035 4.2.2, RFC 7766), served by parley-net's {@link NioServer}.
 * <p>
 * The framework accepts connections, reads them without a thread per connection,
 * splits the input into messages (a {@link LengthFieldFrameDecoder} with the 2 byte
 * length) and applies the limits:
 * <ul>
 * <li>at most maxConnections connections; one more is closed at once (the client
 *     can retry) rather than queued behind idle ones;</li>
 * <li>at most maxConnectionsPerClient from one address (round 5 #72), so one host
 *     can't take every slot;</li>
 * <li>a connection with no traffic for the idle timeout is closed;</li>
 * <li>a message must arrive within the idle timeout once it has started (round 5
 *     #78): a client that sends a byte now and then is never idle, but it can no
 *     longer hold a slot that way.</li>
 * </ul>
 * Each connection has a {@link Connection} handler. Its messages are answered one at a
 * time, in order, on a pool of handler threads (recursion, UPDATE and zone transfers
 * may take a while), never on the threads that read the sockets.
 * <p>
 * The static methods are the API DnsServer and the tests used before (initTCPProsessor,
 * getServerSocket, shutdownConnections...). One TCPProsessor runs the server's accept
 * loop in its own thread; JDns.tcpProcCount is now the number of reactor threads.
 * 
 * Creation date: (8/26/2001 10:41:48 AM)
 * @author: Tony Bringardner
 */
public class TCPProsessor extends DnsRequestProcessor implements Runnable {

	/** Default idle timeout (ms). RFC 7766 6.2.3: seconds, not the 2 minutes of RFC 1035. */
	public static final int DEFAULT_IDLE_TIMEOUT = 10_000;
	/** Default maximum number of connections served at once. */
	public static final int DEFAULT_MAX_CONNECTIONS = 64;
	/** Default maximum number of connections from one client address (round 5 #72). */
	public static final int DEFAULT_MAX_CONNECTIONS_PER_CLIENT = 8;
	/** Largest message a 16 bit TCP length prefix can describe. */
	static final int MAX_TCP_MESSAGE = 0xFFFF;
	/** Bytes queued for one client before a sender (e.g. a zone transfer) waits for it to read. */
	static final int MAX_PENDING_WRITE = 256*1024;

	//  The server of the last initTCPProsessor (null after shutdownConnections)
	private static volatile TcpServer nio;
	//  The listening channel, bound by initTCPProsessor
	private static volatile ServerSocketChannel channel;
	//  Runs the handlers
	private static volatile ThreadPoolExecutor connectionPool;
	private static volatile int idleTimeout = DEFAULT_IDLE_TIMEOUT;
	private static final AtomicLong rejected = new AtomicLong();

	public static volatile boolean debug = false;

	/**
	 * 
	 * Creation date: (8/26/2001 11:37:51 AM)
	 * @param me int
	 */
	public TCPProsessor(DnsServer svr, int me) {
		server   = svr;
	}

	/** The shared TCP listen socket (null before initTCPProsessor). */
	public static ServerSocket getServerSocket() {
		ServerSocketChannel ch = channel;
		return ch == null ? null : ch.socket();
	}

	public static void initTCPProsessor(int bindPort,int backlog,InetAddress bindAddress, int timeout) throws IOException {
		initTCPProsessor(bindPort, backlog, bindAddress, timeout, DEFAULT_MAX_CONNECTIONS, DEFAULT_IDLE_TIMEOUT);
	}

	public static void initTCPProsessor(int bindPort,int backlog,InetAddress bindAddress, int timeout,
			int maxConnections, int idleTimeoutMs) throws IOException {
		initTCPProsessor(bindPort, backlog, bindAddress, timeout, maxConnections, idleTimeoutMs,
				DEFAULT_MAX_CONNECTIONS_PER_CLIENT, 1);
	}

	/**
	 * Bind the TCP port. The server runs once a TCPProsessor is run.
	 * 
	 * @param timeout not used any more (the accept timeout of the blocking acceptors);
	 *  kept as the listen socket's SO_TIMEOUT so it can still be read back
	 * @param maxConnections most connections served at once
	 * @param idleTimeoutMs a connection with no traffic for this long is closed, and
	 *  a message that has started must be complete within it
	 * @param maxPerClient most connections from one client address, 0 for no limit
	 * @param reactors threads reading and writing the connections
	 */
	public synchronized static void initTCPProsessor(int bindPort,int backlog,InetAddress bindAddress, int timeout,
			int maxConnections, int idleTimeoutMs, int maxPerClient, int reactors) throws IOException {
		//  A previous server (re-initialization) is shut down first
		shutdownConnections(1000);

		ServerSocketChannel ch = ServerSocketChannel.open();
		try {
			ch.bind(new InetSocketAddress(bindAddress, bindPort), backlog);
			if( timeout > 0 ) {
				ch.socket().setSoTimeout(timeout);
			}
		} catch(IOException | RuntimeException ex) {
			IoUtils.closeQuietly(ch);
			throw ex;
		}
		idleTimeout = idleTimeoutMs > 0 ? idleTimeoutMs : DEFAULT_IDLE_TIMEOUT;
		int max = maxConnections > 0 ? maxConnections : DEFAULT_MAX_CONNECTIONS;

		//  Admission is limited by the server, so there are never more than max
		//  connections with work queued.
		ThreadPoolExecutor pool = new ThreadPoolExecutor(max, max, 30, TimeUnit.SECONDS,
				new LinkedBlockingQueue<Runnable>(), NamedThreadFactory.numbered("TCPConn"));
		pool.allowCoreThreadTimeOut(true);

		TcpServer s = new TcpServer();
		s.setServerChannel(ch);
		s.setHandlerExecutor(pool);
		s.setReactorCount(Math.max(1, reactors));
		s.setMaxConnections(max);
		s.setMaxConnectionsPerClient(Math.max(0, maxPerClient));
		s.setMaxIdleTime(idleTimeout);
		s.setFrameTimeout(idleTimeout);
		s.setTcpNoDelay(true);
		s.setMaxInputBuffer(4*(MAX_TCP_MESSAGE+2));
		s.setDecoderFactory(() -> new LengthFieldFrameDecoder(2, MAX_TCP_MESSAGE, true));
		s.setServerBusyMessage(null);

		channel = ch;
		connectionPool = pool;
		nio = s;
	}

	/** Number of TCP connections being served now. */
	public static int getActiveConnections() {
		TcpServer s = nio;
		return s == null ? 0 : s.getActiveConnections();
	}

	/** Connections closed at once because maxConnections (or maxConnectionsPerClient) were already open. */
	public static long getRejected() {
		return rejected.get();
	}

	public static int getIdleTimeout() {
		return idleTimeout;
	}

	/** @return the most connections from one client address, 0 for no limit */
	public static int getMaxConnectionsPerClient() {
		TcpServer s = nio;
		return s == null ? DEFAULT_MAX_CONNECTIONS_PER_CLIENT : s.getMaxConnectionsPerClient();
	}

	/**
	 * Stop accepting connections, close every open one and stop the handler threads.
	 * @return true if everything stopped within ms
	 */
	public static boolean shutdownConnections(long ms) {
		long deadline = System.currentTimeMillis()+Math.max(1, ms);
		TcpServer s = nio;
		ThreadPoolExecutor pool = connectionPool;
		ServerSocketChannel ch = channel;
		nio = null;
		connectionPool = null;
		boolean ret = true;
		if( s != null ) {
			s.stop();
			//  The server closes the channel when it stops; it may never have run
			IoUtils.closeQuietly(ch);
			try {
				while( s.isRunning() && System.currentTimeMillis() < deadline ) {
					Thread.sleep(5);
				}
			} catch(InterruptedException ex) {
				Thread.currentThread().interrupt();
				return false;
			}
			ret = !s.isRunning();
		}
		if( pool != null ) {
			pool.shutdownNow();
			try {
				ret &= pool.awaitTermination(Math.max(1, deadline-System.currentTimeMillis()), TimeUnit.MILLISECONDS);
			} catch(InterruptedException ex) {
				Thread.currentThread().interrupt();
				return false;
			}
		}
		return ret;
	}

	/**
	 * Stop accepting connections (DnsServer's closeListeners). Open connections are
	 * closed too; {@link #shutdownConnections(long)} waits for that.
	 */
	public static void closeListener() {
		TcpServer s = nio;
		if( s != null ) {
			s.stop();
		}
		IoUtils.closeQuietly(channel);
	}

	/**
	 * Run the server initTCPProsessor made, until it is stopped. Only one TCPProsessor
	 * runs a given server; another one returns at once.
	 **/
	public void run ()
	{
		TcpServer s = nio;
		if( s == null ) {
			log("Can't run without init");
			setState("No socket, can't run");
			return;
		}
		if( !s.claim() ) {
			setState("Not needed, the server runs in another TCPProsessor");
			return;
		}
		final DnsServer dns = server;
		s.setHandlerFactory(() -> new Connection(dns));
		setState("Running Enter");
		try {
			s.run();
		} finally {
			setState("Running Exit");
		}
	}

	/** Acceptors never answer queries themselves (see Connection). */
	public void sendResponse(Message msg) {
		throw new IllegalStateException("TCPProsessor is an acceptor; responses are sent by Connection");
	}

	/**
	 * Write one length-prefixed DNS message (RFC 1035 4.2.2) to a stream (clients, tests).
	 */
	static void writeMessage(OutputStream out, byte [] data) throws IOException {
		byte [] sz = new byte[2];
		Utility.setShort(sz,0,data.length);
		out.write(sz);
		out.write(data);
		out.flush();
	}

	/** The NIO server: counts rejected connections and sends them nothing. */
	static final class TcpServer extends NioServer {
		private final AtomicBoolean claimed = new AtomicBoolean();

		TcpServer() {
			super(0, "DnsTcp");
		}

		boolean claim() {
			return claimed.compareAndSet(false, true);
		}

		@Override
		protected void rejectBusy(SocketChannel sc) {
			//  No busy message on the DNS port: the connection is just closed
			rejected.incrementAndGet();
		}
	}

	/**
	 * Serves one TCP connection: its messages arrive one at a time, in order, on a
	 * handler thread.
	 */
	static final class Connection extends DnsRequestProcessor implements INioHandler {
		private volatile INioConnection conn;
		private volatile InetAddress client;

		Connection(DnsServer svr) {
			this.server = svr;
		}

		@Override
		public void onConnect(INioConnection connection) {
			conn = connection;
			SocketAddress a = connection.getRemoteAddress();
			client = a instanceof InetSocketAddress ? ((InetSocketAddress)a).getAddress() : null;
			if( DnsServer.isDebug() ) {
				log(() -> "New TCP Connection from "+client);
			}
			setState("Connected", client);
		}

		@Override
		public void onMessage(INioConnection connection, java.nio.ByteBuffer frame) {
			conn = connection;
			if( frame.remaining() < 12 ) {
				//  Smaller than a DNS header: framing is broken
				connection.close();
				return;
			}
			byte [] data = new byte[frame.remaining()];
			frame.get(data);
			ByteBuffer buf = new ByteBuffer(data);
			try {
				if ( debug ) {
					buf.dump();
				}
				Message msg = new Message(buf);
				QueryData query = new QueryData(client,-1,msg);
				query.setWire(data);
				process(query);
			} catch(DnsFormatException ex) {
				// Malformed message: answer FORMERR and drop the connection
				// (framing can't be trusted after a bad message).
				if( DnsServer.isDebug() ) {
					log(() -> "Malformed TCP message from "+client+" "+ex.getMessage());
				}
				sendFormatError(data);
				connection.closeAfterFlush();
			} catch(StackOverflowError ex) {
				log(() -> "StackOverflowError processing TCP message from "+client);
				connection.close();
			} catch(RuntimeException ex) {
				log("Unexpected exception in TCP connection from "+client,ex);
				if( UDPProsessor.dumpBuf != null ) {
					ex.printStackTrace(UDPProsessor.dumpBuf);
					UDPProsessor.dumpBuf.println("TCP Exception "+client);
					buf.dump(UDPProsessor.dumpBuf);
				}
				connection.close();
			}
		}

		/**
		 * The idle check may fire while a slow request (recursion, a zone transfer) is
		 * being answered; it then runs after the answer is sent. Close only if the
		 * connection is still idle.
		 */
		@Override
		public void onIdle(INioConnection connection) {
			long last = Math.max(connection.getLastReadTime(), connection.getLastWriteTime());
			if( System.currentTimeMillis()-last >= idleTimeout ) {
				connection.close();
			}
		}

		@Override
		public void onError(INioConnection connection, Throwable error) {
			if( DnsServer.isDebug() ) {
				log("TCP connection from "+client+" failed", error);
			}
		}

		@Override
		public void onClose(INioConnection connection) {
			setState("Closed", client);
		}

		/**
		 * Reply FORMERR to a TCP request that could not be parsed.
		 */
		private void sendFormatError(byte [] data) {
			byte [] reply = UDPProsessor.buildFormatError(data, data == null ? 0 : data.length);
			if( reply != null ) {
				write(reply);
			}
		}

		public void sendResponse(Message msg) {
			if( msg != null ) {
				Tsig.Session tsig = currentTsig;
				byte [] wire = msg.toByteArray(MAX_TCP_MESSAGE - (tsig == null ? 0 : tsig.reserve()));
				if( tsig != null ) {
					wire = tsig.signResponse(wire);
				}
				if( write(wire) && UDPProsessor.dumpBuf != null ) {
					UDPProsessor.dumpBuf.println("TCP("+client+")->"+msg.toSmallString());
				}
			}
		}

		/**
		 * Queue one message. A client that doesn't read (a zone transfer to a slow or
		 * stalled peer) makes the sender wait here; one that reads nothing for the idle
		 * timeout is disconnected, so a handler thread isn't held for ever.
		 * @return true if the message was queued
		 */
		private boolean write(byte [] wire) {
			INioConnection c = conn;
			if( c == null ) {
				return false;
			}
			try {
				c.write(LengthFieldFrameDecoder.frame(wire, 2));
			} catch(IOException ex) {
				//  closed by the client, the idle timeout or shutdown
				return false;
			}
			long pending = c.getPendingWriteBytes();
			long since = System.currentTimeMillis();
			try {
				while( pending > MAX_PENDING_WRITE && c.isOpen() ) {
					Thread.sleep(2);
					long now = c.getPendingWriteBytes();
					if( now < pending ) {
						since = System.currentTimeMillis();
					} else if( System.currentTimeMillis()-since > idleTimeout ) {
						log(() -> "TCP client "+client+" stopped reading, closing");
						c.close();
						return false;
					}
					pending = now;
				}
			} catch(InterruptedException ex) {
				//  shutdown
				Thread.currentThread().interrupt();
				c.close();
				return false;
			}
			return true;
		}
	}
}
