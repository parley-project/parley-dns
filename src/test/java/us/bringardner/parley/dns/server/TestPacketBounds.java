package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.DnsFormatException;
import us.bringardner.parley.dns.Message;

/**
 * Round 5 #75: reads past the end of a message (a truncated packet, or an
 * RDLENGTH larger than what is left) threw ArrayIndexOutOfBoundsException,
 * which the UDP and TCP workers logged with a stack trace for every packet
 * and answered with nothing. They must be DnsFormatException (FORMERR).
 */
public class TestPacketBounds {

	private static final InetAddress LOOPBACK = InetAddress.getLoopbackAddress();
	private static File dir;
	private static DnsServer server;
	private static Thread udp;
	private static int udpPort;
	private static String savedZoneDir;
	private static String savedMaster;

	/** Header, www.example.com A IN, one answer: example.com A 1.2.3.4 (owner compressed) */
	private static byte [] response() {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		int [] header = {0x12,0x34, 0x81,0x80, 0,1, 0,1, 0,0, 0,0};
		for(int b : header) { o.write(b); }
		byte [] q = {3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0, 0,1, 0,1};
		o.write(q, 0, q.length);
		int [] rr = {0xc0,12, 0,1, 0,1, 0,0,1,0x2c, 0,4, 1,2,3,4};
		for(int b : rr) { o.write(b); }
		return o.toByteArray();
	}

	@Test
	public void elevenBytePacketIsAFormatError() {
		byte [] p = {0x12,0x34,0x01,0x00, 0,1, 0,0, 0,0, 0};
		assertThrows(DnsFormatException.class, () -> new Message(new ByteBuffer(p)));
	}

	@Test
	public void rdlengthPastTheEndIsAFormatError() {
		byte [] ok = response();
		//  RDLENGTH 4 -> 200, the rdata still 4 bytes
		byte [] bad = ok.clone();
		bad[bad.length-5] = (byte)200;
		DnsFormatException ex = assertThrows(DnsFormatException.class, () -> new Message(new ByteBuffer(bad)));
		assertTrue(ex.getMessage().contains("RDLENGTH"), ex.getMessage());
		//  only 2 of the 4 rdata bytes present
		byte [] cut = Arrays.copyOf(ok, ok.length-2);
		assertThrows(DnsFormatException.class, () -> new Message(new ByteBuffer(cut)));
	}

	@Test
	public void everyTruncationIsAFormatError() {
		byte [] ok = response();
		new Message(new ByteBuffer(ok));
		for(int len=0; len < ok.length; len++ ) {
			byte [] cut = Arrays.copyOf(ok, len);
			try {
				new Message(new ByteBuffer(cut));
				fail("length "+len+" parsed");
			} catch(DnsFormatException expected) {
				// ok
			} catch(RuntimeException ex) {
				fail("length "+len+": "+ex);
			}
		}
	}

	@Test
	public void randomDamageOnlyThrowsFormatErrors() {
		byte [] ok = response();
		Random r = new Random(75);
		for(int i=0; i < 20000; i++ ) {
			byte [] b = ok.clone();
			int n = 1+r.nextInt(3);
			for(int k=0; k < n; k++ ) {
				b[12+r.nextInt(b.length-12)] = (byte)r.nextInt(256);
			}
			if( r.nextBoolean() ) {
				b = Arrays.copyOf(b, 12+r.nextInt(b.length-12));
			}
			try {
				new Message(new ByteBuffer(b));
			} catch(DnsFormatException expected) {
				// ok
			} catch(RuntimeException ex) {
				fail("parse threw "+ex+" for "+hex(b));
			}
		}
	}

	// ------------------------------------------------------------ over the wire

	@BeforeAll
	public static void setup() throws Exception {
		dir = Files.createTempDirectory("bounds").toFile();
		try(FileWriter w = new FileWriter(new File(dir,"pb.test.txt"))) {
			w.write("@\tIN\tSOA\tns1.pb.test. postmaster.pb.test. (\n"
					+"\t\t\t1 ; serial\n\t\t\t3600 ; refresh\n\t\t\t1800 ; retry\n"
					+"\t\t\t1209600 ; expire\n\t\t\t300 ) ; minimum\n\n"
					+"\t\tNS\tns1\n"
					+"ns1\tIN\tA\t10.0.0.53\n");
		}
		savedZoneDir = System.getProperty(DnsServer.PROP_ZONE_DIR);
		savedMaster = System.getProperty(DnsServer.PROP_DEFAULT_ZONE);
		System.setProperty(DnsServer.PROP_ZONE_DIR, dir.getAbsolutePath());
		System.setProperty(DnsServer.PROP_DEFAULT_ZONE, "pb.test");
		server = new DnsServer();
		server.loadZones();
		server.setRecursionAvailable(false);
		try(DatagramSocket probe = new DatagramSocket(0, LOOPBACK)) {
			udpPort = probe.getLocalPort();
		}
		DnsServer.setShutdown(false);
		UDPProsessor.initUDPProsessor(udpPort, LOOPBACK, 200);
		udp = new Thread(new UDPProsessor(server,0),"TestPacketBoundsUDP");
		udp.setDaemon(true);
		udp.start();
	}

	@AfterAll
	public static void cleanup() throws Exception {
		DnsServer.setShutdown(true);
		udp.join(3000);
		UDPProsessor.getSock().close();
		DnsServer.setShutdown(false);
		restore(DnsServer.PROP_ZONE_DIR, savedZoneDir);
		restore(DnsServer.PROP_DEFAULT_ZONE, savedMaster);
		for(File f : dir.listFiles()) {
			f.delete();
		}
		dir.delete();
	}

	private static void restore(String k, String v) {
		if( v == null ) {
			System.clearProperty(k);
		} else {
			System.setProperty(k, v);
		}
	}

	private static byte [] udp(byte [] data) throws Exception {
		try(DatagramSocket c = new DatagramSocket(0, LOOPBACK)) {
			c.setSoTimeout(2000);
			c.send(new DatagramPacket(data, data.length, LOOPBACK, udpPort));
			byte [] buf = new byte[4096];
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			try {
				c.receive(p);
			} catch(SocketTimeoutException ex) {
				return null;
			}
			return Arrays.copyOf(buf, p.getLength());
		}
	}

	@Test
	public void truncatedQuestionGetsFormErr() throws Exception {
		//  QDCOUNT=1 but the question stops in the middle of the name
		byte [] req = {0x55,0x66, 0x01,0x00, 0,1, 0,0, 0,0, 0,0, 3,'n','s'};
		byte [] reply = udp(req);
		assertTrue(reply != null, "used to throw ArrayIndexOutOfBoundsException and send nothing");
		Message m = new Message(new ByteBuffer(reply));
		assertEquals(0x5566, m.getID());
		assertEquals(DNS.FORMAT_ERROR, m.getResponseCode());
	}

	@Test
	public void additionalRecordPastTheEndGetsFormErr() throws Exception {
		ByteArrayOutputStream o = new ByteArrayOutputStream();
		int [] h = {0x77,0x01, 0x01,0x00, 0,1, 0,0, 0,0, 0,1};
		for(int b : h) { o.write(b); }
		byte [] q = {3,'n','s','1',2,'p','b',4,'t','e','s','t',0, 0,1, 0,1};
		o.write(q, 0, q.length);
		//  an additional A record that claims 100 bytes of rdata
		int [] rr = {0, 0,1, 0,1, 0,0,0,0, 0,100, 1,2,3,4};
		for(int b : rr) { o.write(b); }
		byte [] reply = udp(o.toByteArray());
		assertTrue(reply != null);
		Message m = new Message(new ByteBuffer(reply));
		assertEquals(0x7701, m.getID());
		assertEquals(DNS.FORMAT_ERROR, m.getResponseCode());
	}

	private static String hex(byte [] b) {
		StringBuilder s = new StringBuilder();
		for(byte x : b) {
			s.append(String.format("%02x", x));
		}
		return s.toString();
	}
}
