package us.bringardner.parley.dns;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.dnssec.Canonical;

/**
 * Names in text form and on the wire (chunk 4: escapes, lengths, ISO-8859-1).
 */
public class TestWireNames {

	private static byte [] wire(String name) {
		ByteBuffer b = new ByteBuffer();
		b.setName(name);
		return b.getByteArray();
	}

	@Test
	public void escapesInText() {
		List<byte[]> l = Name.wireLabels("a\\.b.c\\\\d.\\065x");
		assertEquals(3, l.size());
		assertEquals("a.b", new String(l.get(0), java.nio.charset.StandardCharsets.ISO_8859_1));
		assertEquals("c\\d", new String(l.get(1), java.nio.charset.StandardCharsets.ISO_8859_1));
		assertEquals("Ax", new String(l.get(2), java.nio.charset.StandardCharsets.ISO_8859_1));
		assertThrows(IllegalArgumentException.class, () -> Name.wireLabels("\\300.com"));
	}

	@Test
	public void aNameReadBackPrintsItsEscapes() {
		Name n = new Name(new ByteBuffer(new byte[] {3, 'a', '.', 'b', 3, 'c', 'o', 'm', 0}));
		assertEquals("a\\.b.com", n.toString());
		assertEquals(2, n.getLables().size());
		assertArrayEquals(new byte[] {3, 'a', '.', 'b', 3, 'c', 'o', 'm', 0}, wire(n.toString()));
	}

	@Test
	public void namesThatCantBeWrittenAreRefused() {
		assertThrows(IllegalArgumentException.class, () -> wire("a..b"));
		StringBuilder b = new StringBuilder();
		for(int i=0; i < 5; i++ ) {
			b.append("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghij.");
		}
		assertThrows(IllegalArgumentException.class, () -> wire(b.toString()), "over 255 octets");
		assertEquals(1, wire(".").length);
		assertEquals(1, wire("").length);
		assertEquals(13, wire("example.com.").length, "a trailing dot is the root");
	}

	@Test
	public void highCharactersAreOneOctetUpToU00FF() {
		assertArrayEquals(new byte[] {1, (byte)0xe9, 0}, wire("é"));
		assertArrayEquals(new byte[] {3, (byte)0xe2, (byte)0x82, (byte)0xac, 0}, wire("€"), "above U+00FF: UTF-8");
	}

	@Test
	public void namesCompressToEarlierNames() {
		ByteBuffer b = new ByteBuffer();
		b.setName("www.example.com");
		int at = b.getWritePos();
		b.setName("mail.example.com");
		byte [] w = b.getByteArray();
		//  mail + pointer to example.com (offset 4)
		assertEquals(at+5+2, w.length);
		assertEquals((byte)0xc0, w[w.length-2]);
		assertEquals(4, w[w.length-1]);
		ByteBuffer u = new ByteBuffer();
		u.setName("www.example.com");
		u.setName("www.example.com", false);
		assertEquals(34, u.getByteArray().length, "not compressed when asked");
	}

	@Test
	public void canonicalFormLowerCasesAsciiOnly() {
		ByteBuffer b = new ByteBuffer();
		b.setCanonical(true);
		b.setName("ABÀ.Test");
		assertArrayEquals(new byte[] {3, 'a', 'b', (byte)0xc0, 4, 't', 'e', 's', 't', 0}, b.getByteArray());
		ByteBuffer k = new ByteBuffer();
		k.setCanonical(true);
		k.setNameAsIs("Mixed.Test");
		assertEquals('M', k.getByteArray()[1], "the NSEC next name keeps its case");
	}

	@Test
	public void isBelowComparesLabels() {
		assertTrue(Canonical.isBelow("www.example.com", "example.com", false));
		assertTrue(Canonical.isBelow("example.com", "", false));
		assertTrue(Canonical.isBelow("Example.com.", "example.com", true));
		assertFalse(Canonical.isBelow("example.com", "example.com", false));
		assertFalse(Canonical.isBelow("x\\.example", "example", false), "one label, at the top");
		assertFalse(Canonical.isBelow("com", "example.com", true));
	}

	@Test
	public void anRdLengthOver65535IsRefused() {
		ByteBuffer b = new ByteBuffer();
		b.markPos(0);
		b.setBytes(new byte[70000]);
		assertThrows(IllegalArgumentException.class, b::setRdLength);
	}

	@Test
	public void readingStartsOutsideTheArray() {
		assertThrows(DnsFormatException.class, () -> new ByteBuffer(new byte[2], 5).next());
	}

	@Test
	public void cnameRdataLongerThanTheNameIsAFormatError() {
		//  www.example.com CNAME a.example.com (RDLENGTH 4: 'a' + pointer) declared as 6
		String hdr = "12348180000100010000000003777777076578616d706c6503636f6d0000050001";
		String rr = "c00c000500010000012c00060161c010ffff";
		byte [] b = new byte[(hdr.length()+rr.length())/2];
		String h = hdr+rr;
		for(int i=0; i < b.length; i++ ) {
			b[i] = (byte)Integer.parseInt(h.substring(2*i, 2*i+2), 16);
		}
		assertThrows(DnsFormatException.class, () -> new Message(new ByteBuffer(b)));
	}

	@Test
	public void aTrailingEscapedDotIsPartOfTheLabel() {
		Name n = new Name(new ByteBuffer(new byte[] {2, 'a', '.', 0}));
		assertEquals("a\\.", n.toString());
		assertEquals(n, new Name(n.toString()));
		assertArrayEquals(new byte[] {2, 'a', '.', 0}, wire(n.toString()));
		assertEquals("a\\.", Name.stripRootDot("a\\."));
		assertEquals("a\\\\", Name.stripRootDot("a\\\\."));
		assertEquals("a\\\\", Canonical.key("a\\\\."));
		assertEquals("a\\.", Canonical.key("A\\."));
	}

	@Test
	public void compressionKeysDontConfuseLabelsWithNames() {
		ByteBuffer b = new ByteBuffer();
		b.setName("a\\000b");
		b.setName("a.b");
		ByteBuffer r = new ByteBuffer(b.getByteArray());
		assertEquals("a\u0000b", new Name(r).toString());
		assertEquals("a.b", new Name(r).toString());
	}

	@Test
	public void aTxtStringRunningPastTheRdataIsAFormatError() {
		//  TXT with RDLENGTH 3: a string of 5 bytes
		String hdr = "12348180000100010000000003777777076578616d706c6503636f6d0000100001";
		String rr = "c00c001000010000012c0003056162";
		String h = hdr+rr;
		byte [] b = new byte[h.length()/2];
		for(int i=0; i < b.length; i++ ) {
			b[i] = (byte)Integer.parseInt(h.substring(2*i, 2*i+2), 16);
		}
		assertThrows(DnsFormatException.class, () -> new Message(new ByteBuffer(b)));
	}

	@Test
	public void anAfsdbIsSentAsAnAfsdb() {
		Afsdb a = new Afsdb("example.com");
		assertEquals(DNS.AFSDB, a.getType());
	}

	@Test
	public void aWrittenBufferCanBeReadBackPastItsFirstSize() {
		ByteBuffer b = new ByteBuffer(new byte[4], 0);
		for(int i=0; i < 10; i++ ) {
			b.setShort(i);
		}
		for(int i=0; i < 10; i++ ) {
			assertEquals(i, b.nextShort());
		}
	}
}
