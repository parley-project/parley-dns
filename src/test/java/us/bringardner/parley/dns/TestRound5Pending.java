package us.bringardner.parley.dns;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.dnssec.Canonical;

/**
 * Round 5 findings in the wire format code that a later chunk of the
 * framework plan fixes (claude/parley-framework-plan.md). They fail today and
 * are disabled; the chunk that fixes one removes its @Disabled.
 * <p>
 * To run them anyway: mvn test -Dtest=TestRound5Pending
 * -Djunit.jupiter.conditions.deactivate=org.junit.*DisabledCondition
 */
public class TestRound5Pending {

	private static byte [] h(String s) {
		byte [] b = new byte[s.length()/2];
		for(int i=0; i < b.length; i++ ) {
			b[i] = (byte)Integer.parseInt(s.substring(2*i, 2*i+2), 16);
		}
		return b;
	}

	private static Message parse(byte [] wire) {
		return new Message(new ByteBuffer(wire));
	}

	/** Header (response, 1 question, 2 answers), question www.example.com MX IN */
	private static final String MX_HEADER = "12348180000100020000000003777777076578616d706c6503636f6d00000f0001";

	@Test
	@Disabled("Round 5 #79: chunk 4 (rdata bounded by RDLENGTH)")
	public void rdataShorterThanItsTypeIsAFormatError() {
		//  MX with RDLENGTH 2 (the preference only): the exchange used to be read
		//  from the next record's owner name (mail.example.com)
		String mx = "c00c000f00010000012c0002000a";
		String next = "046d61696cc010000100010000012c000401020304";
		assertThrows(DnsFormatException.class, () -> parse(h(MX_HEADER+mx+next)));
	}

	@Test
	@Disabled("Round 5 #79: chunk 4 (rdata must use exactly RDLENGTH bytes)")
	public void rdataLongerThanItsContentIsAFormatError() {
		//  MX 10 mail.example.com (RDLENGTH 9) declared as 12 bytes, 3 bytes of junk after
		String mx = "c00c000f00010000012c000c000a046d61696cc010ffffff";
		String hdr = "12348180000100010000000003777777076578616d706c6503636f6d00000f0001";
		assertThrows(DnsFormatException.class, () -> parse(h(hdr+mx)));
	}

	@Test
	@Disabled("Round 5 #95: chunk 4 (A and AAAA check their RDLENGTH)")
	public void anARecordWithOneByteIsAFormatError() {
		String one = "12348180000100010000000003777777076578616d706c6503636f6d0000010001c00c000100010000012c000101";
		assertThrows(DnsFormatException.class, () -> parse(h(one)));
	}

	@Test
	@Disabled("Round 5 #95: chunk 4 (Section.toString range checks)")
	public void unusualTypesAndClassesCanBePrinted() {
		//  class NONE (254) comes with every UPDATE that deletes a record
		new Section("x.example.com", DNS.A, 254).toString();
		new Section("x.example.com", 300, DNS.IN).toString();
	}

	@Test
	@Disabled("Round 5 #81: chunk 4 (names written as Latin-1, as they are read)")
	public void aLabelWithAHighByteIsEchoedUnchanged() {
		byte [] q = h("123401000001000000000000"+"01e9076578616d706c6503636f6d0000010001");
		byte [] out = parse(q).toByteArray();
		assertArrayEquals(q, out, "the echoed question was UTF-8 (c3a9) with a length of 1");
	}

	@Test
	@Disabled("Round 5 #82: chunk 4 (a '.' inside a label is not a separator)")
	public void aDotInsideALabelIsKept() {
		byte [] q = h("123401000001000000000000"+"03612e6203636f6d0000010001");
		assertArrayEquals(q, parse(q).toByteArray(), "the label a.b went out as two labels a and b");
	}

	@Test
	@Disabled("Round 5 #82: chunk 4 (labels over 63 bytes are not written)")
	public void aLabelOver63BytesCantBeWritten() {
		StringBuilder label = new StringBuilder();
		for(int i=0; i < 70; i++ ) {
			label.append('x');
		}
		Message m = new Message();
		m.setQuestion(label+".com", DNS.A, DNS.IN);
		//  it used to be written with length byte 0x46, which reads back as a reserved label type
		assertThrows(RuntimeException.class, () -> m.toByteArray());
	}

	@Test
	@Disabled("Round 5 #80: chunk 4 (no compression pointers past offset 0x3FFF)")
	public void namesPast16KiBAreWrittenCorrectly() {
		Message m = new Message();
		m.setQuestion("example.com", DNS.MX, DNS.IN);
		for(int i=0; i < 1500; i++ ) {
			Mx mx = new Mx("example.com");
			mx.setPref((short)i);
			mx.setExchange("mx"+i+".example.com");
			m.addAnswer(mx);
		}
		for(int i=0; i < 1500; i += 100 ) {
			A a = new A("mx"+i+".example.com");
			a.setAddress("10.0.0.1");
			m.addAdditional(a);
		}
		byte [] w = m.toByteArray();
		Message back = parse(w);
		for(int i=0; i < m.getAdditional().size(); i++ ) {
			assertEquals(m.getAdditional().get(i).getName().toLowerCase(), back.getAdditional().get(i).getName().toLowerCase(), "additional "+i);
		}
	}

	@Test
	@Disabled("Round 5 #96: chunk 4 (RP and AFSDB names not compressed, RFC 3597 4)")
	public void rpNamesAreNotCompressed() {
		Message m = parse(h("12348180000100010000000003777777076578616d706c6503636f6d0000110001c00c001100010000012c0018"
				+"0561646d696e076578616d706c6503636f6d00"+"03747874c010"));
		RR rp = parse(m.toByteArray()).getAnswer().get(0);
		//  admin.example.com. (19 bytes) + txt.example.com. (17 bytes), no pointers
		assertEquals(36, rp.getRdata().length);
	}

	@Test
	@Disabled("Round 5 #93: chunk 4 (canonical form lower-cases A-Z only, RFC 4034 6.2)")
	public void onlyAsciiLettersAreLowerCased() {
		assertEquals("aÀ.test", Canonical.key("AÀ.Test"));
	}
}
