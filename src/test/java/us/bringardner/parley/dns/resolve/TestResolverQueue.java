package us.bringardner.parley.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Section;
import us.bringardner.parley.dns.server.UDPProsessor;

/**
 * Chunk 6: the resolver queue (round 4 #58, #59, #70) and virtual resolver threads.
 */
public class TestResolverQueue {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private final List<ResolverThread> threads = new ArrayList<ResolverThread>();
	private long savedAge;

	/** An upstream that answers every A query after a delay, counting the queries. */
	static final class SlowUpstream implements AutoCloseable {
		final DatagramSocket sock;
		final AtomicInteger received = new AtomicInteger();
		private volatile boolean running = true;

		SlowUpstream(int delayMs) throws Exception {
			sock = new DatagramSocket(0, LOOPBACK);
			Thread t = new Thread(() -> {
				while( running ) {
					try {
						byte [] buf = new byte[DNS.MAXUDPLEN];
						DatagramPacket p = new DatagramPacket(buf, buf.length);
						sock.receive(p);
						received.incrementAndGet();
						Message req = new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
						InetAddress to = p.getAddress();
						int port = p.getPort();
						Thread r = new Thread(() -> {
							try {
								Thread.sleep(delayMs);
								Message m = new Message();
								m.setHeader(req.getHeader().copy());
								m.setMessageTypeResponse();
								Section q = req.getFirstQuestion();
								m.setQuestion(q);
								A a = new A(q.getName());
								a.setAddress("10.6.6.6");
								a.setTTL(60);
								m.addAnswer(a);
								byte [] d = m.toByteArray();
								sock.send(new DatagramPacket(d, d.length, to, port));
							} catch(Exception ex) {
							}
						});
						r.setDaemon(true);
						r.start();
					} catch(Exception ex) {
						//  closed
					}
				}
			}, "SlowUpstream");
			t.setDaemon(true);
			t.start();
		}

		int port() {
			return sock.getLocalPort();
		}

		@Override
		public void close() {
			running = false;
			sock.close();
		}
	}

	@BeforeEach
	public void setup() throws Exception {
		savedAge = ResolverThread.getMaxQueueAge();
		ResolverThread.clearBacklog();
		Resolver.getCache().clear();
		int port;
		try(DatagramSocket probe = new DatagramSocket(0, LOOPBACK)) {
			port = probe.getLocalPort();
		}
		UDPProsessor.initUDPProsessor(port, LOOPBACK, 200);
	}

	@AfterEach
	public void cleanup() throws Exception {
		for(ResolverThread t : threads) {
			t.stop();
			t.join(2000);
		}
		ResolverThread.setMaxQueueAge(savedAge);
		ResolverThread.setVirtualThreads(true);
		UDPProsessor.getSock().close();
		ResolverThread.clearBacklog();
		Resolver.setRootServersForTests(Collections.<RemoteServer>emptyList());
		Resolver.getCache().clear();
	}

	private void startThreads(int n) throws Exception {
		for(int i=0; i < n; i++ ) {
			ResolverThread t = new ResolverThread();
			t.start("TestResolverQueue"+i);
			threads.add(t);
		}
	}

	private static Message request(String name, int id) {
		Message m = new Message();
		m.setQuestion(name, DNS.A, DNS.IN);
		m.setID(id);
		m.getHeader().setRD(true);
		return m;
	}

	private static Message receive(DatagramSocket client) throws Exception {
		byte [] buf = new byte[DNS.MAXUDPLEN];
		DatagramPacket p = new DatagramPacket(buf, buf.length);
		client.receive(p);
		return new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
	}

	private static void useUpstream(int port) {
		RemoteServer root = new RemoteServer();
		root.setName(".");
		root.addAddress("a.root.test", "127.0.0.1");
		root.iterator().next().setPort(port);
		Resolver.setRootServersForTests(Collections.singletonList(root));
	}

	@Test
	public void aQueryThatWaitedTooLongIsDropped() throws Exception {
		ResolverThread.setMaxQueueAge(50);
		try(DatagramSocket client = new DatagramSocket(0, LOOPBACK)) {
			client.setSoTimeout(1000);
			long staleBefore = ResolverThread.getStale();
			assertTrue(ResolverThread.addQuery(new QueryData(LOOPBACK, client.getLocalPort(), request("late.queue.test", 7))));
			Thread.sleep(150);
			startThreads(1);
			long end = System.currentTimeMillis()+3000;
			while( ResolverThread.getStale() == staleBefore && System.currentTimeMillis() < end ) {
				Thread.sleep(10);
			}
			assertEquals(staleBefore+1, ResolverThread.getStale());
			try {
				receive(client);
				throw new AssertionError("the client gave up long ago: no answer");
			} catch(SocketTimeoutException expected) {
			}
		}
	}

	@Test
	public void identicalLookupsShareOneUpstreamQuery() throws Exception {
		ResolverThread.setMaxQueueAge(0);
		try(SlowUpstream up = new SlowUpstream(400); DatagramSocket client = new DatagramSocket(0, LOOPBACK)) {
			useUpstream(up.port());
			client.setSoTimeout(5000);
			startThreads(4);
			long coalescedBefore = ResolverThread.getCoalesced();
			int n = 6;
			for(int i=0; i < n; i++ ) {
				assertTrue(ResolverThread.addQuery(new QueryData(LOOPBACK, client.getLocalPort(), request("same.queue.test", 100+i))));
			}
			java.util.Set<Integer> ids = new java.util.HashSet<Integer>();
			for(int i=0; i < n; i++ ) {
				Message m = receive(client);
				assertEquals(DNS.NOERROR, m.getResponseCode());
				assertEquals(1, m.getAnswerCount(), "every client gets the answer");
				ids.add(m.getID());
			}
			assertEquals(n, ids.size());
			assertEquals(1, up.received.get(), "one upstream query for "+n+" clients");
			assertTrue(ResolverThread.getCoalesced() >= coalescedBefore+3, "the others waited for it");
		}
	}

	@Test
	public void differentNamesAreNotCoalesced() throws Exception {
		ResolverThread.setMaxQueueAge(0);
		try(SlowUpstream up = new SlowUpstream(100); DatagramSocket client = new DatagramSocket(0, LOOPBACK)) {
			useUpstream(up.port());
			client.setSoTimeout(5000);
			startThreads(2);
			assertTrue(ResolverThread.addQuery(new QueryData(LOOPBACK, client.getLocalPort(), request("one.queue.test", 1))));
			assertTrue(ResolverThread.addQuery(new QueryData(LOOPBACK, client.getLocalPort(), request("two.queue.test", 2))));
			receive(client);
			receive(client);
			assertEquals(2, up.received.get());
		}
	}

	@Test
	public void keysIgnoreCaseAndSeparateCd() {
		Section a = new Section("WWW.Example.com", DNS.A, DNS.IN);
		Section b = new Section("www.example.com.", DNS.A, DNS.IN);
		assertEquals(ResolverThread.coalesceKey(a, false), ResolverThread.coalesceKey(b, false));
		assertTrue(!ResolverThread.coalesceKey(a, false).equals(ResolverThread.coalesceKey(a, true)));
		assertTrue(!ResolverThread.coalesceKey(a, false).equals(ResolverThread.coalesceKey(new Section("www.example.com", DNS.AAAA, DNS.IN), false)));
	}

	@Test
	public void resolverThreadsAreVirtualWhereTheJvmHasThem() throws Exception {
		int feature = Runtime.version().feature();
		ResolverThread.setVirtualThreads(true);
		startThreads(1);
		java.lang.reflect.Field f = ResolverThread.class.getDeclaredField("thread");
		f.setAccessible(true);
		Thread t = (Thread)f.get(threads.get(0));
		boolean virtual = (Boolean)Thread.class.getMethod("isVirtual").invoke(t);
		assertEquals(feature >= 21, virtual);
		ResolverThread.setVirtualThreads(false);
		startThreads(1);
		t = (Thread)f.get(threads.get(1));
		assertEquals(false, (Boolean)Thread.class.getMethod("isVirtual").invoke(t));
	}

	@Test
	public void theQueueIsBounded() throws Exception {
		int cap = ResolverThread.getMaxBackLog();
		long droppedBefore = ResolverThread.getDropped();
		for(int i=0; i < cap; i++ ) {
			assertTrue(ResolverThread.addQuery(new QueryData(LOOPBACK, 9, request("q"+i+".queue.test", i))));
		}
		assertEquals(cap, ResolverThread.getBacklog());
		assertTrue(!ResolverThread.addQuery(new QueryData(LOOPBACK, 9, request("full.queue.test", 1))));
		assertEquals(droppedBefore+1, ResolverThread.getDropped());
		assertEquals(cap, ResolverThread.clearBacklog());
		assertEquals(0, ResolverThread.getBacklog());
	}
}
