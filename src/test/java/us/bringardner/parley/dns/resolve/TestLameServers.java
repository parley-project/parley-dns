package us.bringardner.parley.dns.resolve;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Ns;
import us.bringardner.parley.dns.Section;

/**
 * Round 4 #62: lame or refusing servers don't rank first, and a referral that
 * leads nowhere closer is no answer.
 */
public class TestLameServers {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();

	/** Answers every query with what the function makes of it. */
	static final class Upstream implements AutoCloseable {
		final DatagramSocket sock;
		final AtomicInteger received = new AtomicInteger();

		Upstream(UnaryOperator<Message> answer) throws Exception {
			sock = new DatagramSocket(0, LOOPBACK);
			Thread t = new Thread(() -> {
				while( !sock.isClosed() ) {
					try {
						byte [] buf = new byte[DNS.MAXUDPLEN];
						DatagramPacket p = new DatagramPacket(buf, buf.length);
						sock.receive(p);
						received.incrementAndGet();
						Message req = new Message(new ByteBuffer(java.util.Arrays.copyOf(buf, p.getLength())));
						Message r = new Message();
						r.setHeader(req.getHeader().copy());
						r.setMessageTypeResponse();
						r.setQuestion(req.getFirstQuestion());
						byte [] d = answer.apply(r).toByteArray();
						sock.send(new DatagramPacket(d, d.length, p.getSocketAddress()));
					} catch(Exception ex) {
						//  closed
					}
				}
			}, "LameUpstream");
			t.setDaemon(true);
			t.start();
		}

		int port() {
			return sock.getLocalPort();
		}

		@Override
		public void close() {
			sock.close();
		}
	}

	static Message refused(Message r) {
		r.setResponseCode(DNS.REFUSED);
		return r;
	}

	static Message answer(Message r) {
		A a = new A(r.getFirstQuestion().getName());
		a.setAddress("10.4.4.4");
		a.setTTL(60);
		r.addAnswer(a);
		return r;
	}

	/** A referral to the root: upwards, from any server below it. */
	static Message upward(Message r) {
		Ns ns = new Ns("");
		ns.setNs("a.root-servers.net");
		ns.setTTL(3600);
		r.addAuthority(ns);
		return r;
	}

	@AfterEach
	public void cleanup() {
		Resolver.setRootServersForTests(Collections.<RemoteServer>emptyList());
		Resolver.getCache().clear();
	}

	private static ServerA server(int port) {
		ServerA s = new ServerA("ns.lame.test", "127.0.0.1");
		s.setPort(port);
		return s;
	}

	@Test
	public void aRefusalCountsAsAFailure() throws Exception {
		try(Upstream up = new Upstream(TestLameServers::refused)) {
			ServerA s = server(up.port());
			Message m = s.query(new Section("www.lame.test", DNS.A, DNS.IN));
			assertNotNull(m, "the answer is still returned");
			assertEquals(DNS.REFUSED, m.getResponseCode());
			assertEquals(1, s.getHealth().getConsecutiveFailures());
			assertTrue(s.getSrtt() >= 2*ServerA.QUERY_TIMEOUT, "ranked like a timeout: "+s.getSrtt());
		}
	}

	@Test
	public void aLameReferralIsSkippedAndCounted() throws Exception {
		try(Upstream lame = new Upstream(TestLameServers::upward); Upstream good = new Upstream(TestLameServers::answer)) {
			RemoteServer zone = new RemoteServer("lame.test");
			zone.addAddress("ns1.lame.test", "127.0.0.1");
			zone.addAddress("ns2.lame.test", "127.0.0.2");
			ServerA bad = null;
			ServerA ok = null;
			for(java.util.Iterator<ServerA> it = zone.iterator(); it.hasNext(); ) {
				ServerA s = it.next();
				if( s.getName().startsWith("ns1") ) {
					bad = s;
				} else {
					ok = s;
				}
			}
			bad.setPort(lame.port());
			ok.setAddress("127.0.0.1");
			ok.setPort(good.port());
			for(int i=0; i < 4; i++ ) {
				Message m = zone.resolve(new Section("www.lame.test", DNS.A, DNS.IN), System.currentTimeMillis()+3000);
				assertNotNull(m);
				assertEquals(1, m.getAnswerCount(), "the working server answers");
			}
			assertTrue(bad.getHealth().getConsecutiveFailures() > 0 || !bad.isActive(), "the lame one is counted as failing");
		}
	}

	@Test
	public void onlyLameReferralsIsNoAnswer() throws Exception {
		try(Upstream lame = new Upstream(TestLameServers::upward)) {
			RemoteServer root = new RemoteServer();
			root.setName("lame.test");
			root.addAddress("ns.lame.test", "127.0.0.1");
			root.iterator().next().setPort(lame.port());
			Resolver.getCache().clear();
			Resolver.setRootServersForTests(Collections.singletonList(root));
			assertNull(Resolver.resolve(new Section("www.lame.test", DNS.A, DNS.IN)), "SERVFAIL, not NOERROR without data");
		}
	}

	// ------------------------------------------------------------ round 4 #64, bailiwick

	/** evil.test's server: a CNAME to bank.test plus a made-up address for it. */
	static Message poison(Message r) {
		String q = r.getFirstQuestion().getName();
		if( q.equalsIgnoreCase("www.evil.test") ) {
			us.bringardner.parley.dns.Cname c = new us.bringardner.parley.dns.Cname("www.evil.test");
			c.setCname("www.bank.test");
			c.setTTL(60);
			r.addAnswer(c);
		}
		A a = new A("www.bank.test");
		a.setAddress("6.6.6.6");
		a.setTTL(60);
		r.addAnswer(a);
		return r;
	}

	@Test
	public void recordsOutsideTheZoneAskedAreDropped() throws Exception {
		try(Upstream evil = new Upstream(TestLameServers::poison)) {
			RemoteServer zone = new RemoteServer();
			zone.setName("evil.test");
			zone.addAddress("ns.evil.test", "127.0.0.1");
			zone.iterator().next().setPort(evil.port());
			Resolver.getCache().clear();
			Resolver.setRootServersForTests(Collections.singletonList(zone));
			Message m = Resolver.resolve(new Section("www.evil.test", DNS.A, DNS.IN));
			if( m != null ) {
				for(us.bringardner.parley.dns.RR rr : m.getAnswer()) {
					assertTrue(rr.getType() != DNS.A, "the address of www.bank.test from evil.test's server: "+rr);
				}
			}
			assertNull(Resolver.getCache().get(new Section("www.bank.test", DNS.A, DNS.IN)), "nothing cached for bank.test");
		}
	}

	@Test
	public void scrubAndChainEnd() {
		Message m = new Message();
		m.setQuestion("a.zone.test", DNS.A, DNS.IN);
		us.bringardner.parley.dns.Cname c1 = new us.bringardner.parley.dns.Cname("a.zone.test");
		c1.setCname("b.zone.test");
		us.bringardner.parley.dns.Cname c2 = new us.bringardner.parley.dns.Cname("b.zone.test");
		c2.setCname("c.other.test");
		A out = new A("c.other.test");
		out.setAddress("6.6.6.6");
		m.addAnswer(c1);
		m.addAnswer(c2);
		m.addAnswer(out);
		Resolver.scrub(m, "zone.test");
		assertEquals(2, m.getAnswerCount(), "the CNAMEs stay, the other zone's address goes");
		assertEquals("c.other.test", Resolver.unansweredChainEnd(m, new Section("a.zone.test", DNS.A, DNS.IN)));
		A in = new A("c.other.test");
		in.setAddress("10.1.1.1");
		m.addAnswer(in);
		assertNull(Resolver.unansweredChainEnd(m, new Section("a.zone.test", DNS.A, DNS.IN)), "complete");
		assertEquals(3, Resolver.scrub(m, ".").getAnswerCount(), "the root may speak for everything");
	}
}
