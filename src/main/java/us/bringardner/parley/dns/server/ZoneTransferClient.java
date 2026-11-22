package us.bringardner.parley.dns.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import us.bringardner.parley.dns.ByteBuffer;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.DnsBaseClass;
import us.bringardner.parley.dns.DnsTransport;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Soa;
import us.bringardner.parley.dns.Tsig;

/**
 * The client side of a zone transfer: asks a primary for a zone's SOA (to see
 * whether it has a newer one) and for the whole zone (AXFR, RFC 5936), over
 * TCP, signed with a TSIG key when there is one.
 * <p>
 * Every answer must come from the primary asked, carry the zone's own names
 * only, and (when a key is used) be signed by that key; anything else is
 * thrown away and reported as an {@link IOException}, so a bad transfer never
 * replaces a good zone.
 * <p>
 * A transfer with a key requires every message to be signed. A primary that
 * signs only some of the messages of a long transfer (RFC 8945 5.3.1 allows
 * it) is not supported; parley-dns signs every message.
 */
public class ZoneTransferClient extends DnsBaseClass {

	/** What a transfer brings: the zone's SOA and its other records, in the order sent. */
	public static final class Transfer {
		private final Soa soa;
		private final List<RR> records;

		Transfer(Soa soa, List<RR> records) {
			this.soa = soa;
			this.records = records;
		}

		public Soa getSoa() {
			return soa;
		}

		/** Every record but the SOA (which is {@link #getSoa()}). */
		public List<RR> getRecords() {
			return records;
		}
	}

	/** Default time for a whole transfer, in ms. */
	public static final int DEFAULT_TIMEOUT = 60000;

	private final InetSocketAddress primary;
	private final Tsig.Key key;
	private final int fudge;
	private final int timeout;
	private final SecureRandom random = new SecureRandom();

	public ZoneTransferClient(InetSocketAddress primary, Tsig.Key key, int fudge, int timeoutMs) {
		this.primary = primary;
		this.key = key;
		this.fudge = Tsig.checkFudge(fudge);
		this.timeout = Math.max(1, timeoutMs);
	}

	public InetSocketAddress getPrimary() {
		return primary;
	}

	/**
	 * The serial of the zone's SOA at the primary (an unsigned 32 bit number in an int).
	 *
	 * @throws IOException if the primary can't be reached, refuses, or answers badly
	 */
	public int fetchSerial(String zone) throws IOException {
		long end = System.currentTimeMillis()+timeout;
		try(Socket sock = connect(end)) {
			Tsig.Session tsig = send(sock, zone, DNS.SOA);
			Message m = receive(sock, tsig, end, zone, DNS.SOA);
			Soa soa = null;
			for(RR rr : m.getAnswer()) {
				if( rr.getType() == DNS.SOA && sameName(rr.getName(), zone) ) {
					soa = (Soa)rr;
				}
			}
			if( soa == null ) {
				throw new IOException("The primary "+primary+" sent no SOA for "+zone);
			}
			return soa.getSerial();
		}
	}

	/**
	 * Transfer the whole zone.
	 *
	 * @throws IOException if the transfer is refused, cut off, not signed as it should be, or holds a name outside the zone
	 */
	public Transfer transfer(String zone) throws IOException {
		long end = System.currentTimeMillis()+timeout;
		try(Socket sock = connect(end)) {
			Tsig.Session tsig = send(sock, zone, DNS.AXFR);
			Soa first = null;
			List<RR> records = new ArrayList<RR>();
			while( true ) {
				Message m = receive(sock, tsig, end, zone, DNS.AXFR);
				List<RR> answers = m.getAnswer();
				if( answers.isEmpty() ) {
					throw new IOException("The primary "+primary+" sent a message with no records in the transfer of "+zone);
				}
				for(RR rr : answers) {
					if( !inZone(rr.getName(), zone) ) {
						throw new IOException("The transfer of "+zone+" from "+primary+" holds "+rr.getName()+", which is not in the zone");
					}
					if( first == null ) {
						if( rr.getType() != DNS.SOA || !sameName(rr.getName(), zone) ) {
							throw new IOException("The transfer of "+zone+" from "+primary+" did not start with the zone's SOA");
						}
						first = (Soa)rr;
					} else if( rr.getType() == DNS.SOA && sameName(rr.getName(), zone) ) {
						//  the SOA that ends the transfer
						if( ((Soa)rr).getSerial() != first.getSerial() ) {
							throw new IOException("The zone "+zone+" changed on "+primary+" during the transfer (serial "
									+Integer.toUnsignedString(first.getSerial())+" then "+Integer.toUnsignedString(((Soa)rr).getSerial())+")");
						}
						return new Transfer(first, records);
					} else {
						records.add(rr);
					}
				}
			}
		}
	}

	private Socket connect(long end) throws IOException {
		Socket sock = new Socket();
		try {
			sock.connect(primary, DnsTransport.remaining(end));
			return sock;
		} catch(IOException | RuntimeException e) {
			try {
				sock.close();
			} catch(IOException ignore) {
				//  the original failure is the news
			}
			throw e;
		}
	}

	private Tsig.Session send(Socket sock, String zone, int type) throws IOException {
		Message m = new Message();
		m.setID(random.nextInt(0x10000));
		m.getHeader().setRD(false);
		m.setQuestion(zone, type, DNS.IN);
		byte [] data = m.toByteArray();
		Tsig.Session tsig = null;
		if( key != null ) {
			tsig = Tsig.Session.client(key, fudge);
			data = tsig.signRequest(data);
		}
		sock.getOutputStream().write(DnsTransport.frame(data));
		sock.getOutputStream().flush();
		return tsig;
	}

	private Message receive(Socket sock, Tsig.Session tsig, long end, String zone, int type) throws IOException {
		byte [] wire = DnsTransport.readFramed(sock, end);
		Message m;
		try {
			m = new Message(new ByteBuffer(wire));
		} catch(RuntimeException e) {
			throw new IOException("The primary "+primary+" sent a message that is not DNS: "+e.getMessage(), e);
		}
		if( tsig != null ) {
			try {
				tsig.verifyResponse(wire);
			} catch(Tsig.TsigException e) {
				throw new IOException("The answer for "+zone+" from "+primary+" is not signed with our key: "+e.getMessage(), e);
			}
		}
		if( m.isQuery() ) {
			throw new IOException("The primary "+primary+" sent a query, not an answer");
		}
		int rcode = m.getResponseCode();
		if( rcode != DNS.NOERROR ) {
			throw new IOException("The primary "+primary+" answered the "+(type == DNS.AXFR ? "transfer" : "SOA query")+" of "+zone
					+" with RCODE "+rcode+(rcode == DNS.REFUSED ? " (REFUSED: it must allow this server with parley.dns.axfrAllow, or sign with a key in parley.dns.axfrKeys)" : ""));
		}
		return m;
	}

	static boolean sameName(String a, String b) {
		return strip(a).equalsIgnoreCase(strip(b));
	}

	/** Is the name the zone's or under it? */
	static boolean inZone(String name, String zone) {
		String n = strip(name).toLowerCase();
		String z = strip(zone).toLowerCase();
		return n.equals(z) || n.endsWith("."+z);
	}

	static String strip(String name) {
		return name != null && name.endsWith(".") ? name.substring(0, name.length()-1) : name;
	}
}
