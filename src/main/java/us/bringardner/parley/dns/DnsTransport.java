package us.bringardner.parley.dns;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.function.Predicate;

/**
 * The parts of sending a DNS message that every client here needs: TCP framing (RFC 1035 section
 * 4.2.2) and waiting for a datagram answer. Callers decide what a good answer is.
 */
public final class DnsTransport {

	/** The largest datagram a DNS answer can be. */
	private static final int MAX_DATAGRAM = 65535;

	private DnsTransport() {
	}

	/** A message with the two byte length TCP puts in front of it, in one array so it goes out in one write. */
	public static byte[] frame(byte[] message) {
		byte[] framed = new byte[2 + message.length];
		framed[0] = (byte) (message.length >> 8);
		framed[1] = (byte) message.length;
		System.arraycopy(message, 0, framed, 2, message.length);
		return framed;
	}

	/**
	 * Read one length-prefixed message from a connection, giving up at {@code end}: the socket
	 * timeout is set to the time left before every read, so the whole read is bounded and a server
	 * sending a byte now and then can't hold the caller.
	 *
	 * @param end the time (ms since the epoch) to give up
	 * @throws SocketTimeoutException if {@code end} passes
	 * @throws IOException at end of stream before the whole message
	 */
	public static byte[] readFramed(Socket sock, long end) throws IOException {
		InputStream in = sock.getInputStream();
		byte[] size = new byte[2];
		readFully(sock, in, size, end);
		byte[] message = new byte[((size[0] & 0xff) << 8) | (size[1] & 0xff)];
		readFully(sock, in, message, end);
		return message;
	}

	/** The ms left until {@code end}, at least 1 (a socket timeout of 0 would mean forever). */
	public static int remaining(long end) throws SocketTimeoutException {
		long left = end - System.currentTimeMillis();
		if (left <= 0) {
			throw new SocketTimeoutException("Deadline passed");
		}
		return (int) Math.min(Integer.MAX_VALUE, left);
	}

	private static void readFully(Socket sock, InputStream in, byte[] ba, long end) throws IOException {
		int pos = 0;
		while (pos < ba.length) {
			sock.setSoTimeout(remaining(end));
			int cnt = in.read(ba, pos, ba.length - pos);
			if (cnt == -1) {
				throw new IOException("Unexpected EOF reading a DNS message");
			}
			pos += cnt;
		}
	}

	/**
	 * Wait for an answer datagram.
	 *
	 * @param sock the socket the query was sent from
	 * @param from if not null, datagrams from any other address or port are ignored
	 * @param deadline the time (ms since the epoch) to give up
	 * @param accept looks at a datagram's bytes (only those received); true if it is the answer
	 * @param onRejected called for every datagram that is not the answer; may be null
	 * @return the bytes of the first accepted datagram, or null if {@code deadline} passed
	 */
	public static byte[] udpAwait(DatagramSocket sock, InetSocketAddress from, long deadline, Predicate<byte[]> accept,
			Runnable onRejected) throws IOException {
		byte[] buf = new byte[MAX_DATAGRAM];
		while (true) {
			long remaining = deadline - System.currentTimeMillis();
			if (remaining <= 0) {
				return null;
			}
			sock.setSoTimeout((int) Math.min(Integer.MAX_VALUE, remaining));
			DatagramPacket p = new DatagramPacket(buf, buf.length);
			try {
				sock.receive(p);
			} catch (SocketTimeoutException e) {
				return null;
			}
			byte[] wire = Arrays.copyOf(buf, p.getLength());
			if ((from == null || (from.getAddress().equals(p.getAddress()) && from.getPort() == p.getPort()))
					&& accept.test(wire)) {
				return wire;
			}
			if (onRejected != null) {
				onRejected.run();
			}
		}
	}
}
