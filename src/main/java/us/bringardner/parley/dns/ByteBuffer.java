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
package us.bringardner.parley.dns;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import us.bringardner.parley.io.WireBuffer;
/**
This class manages the creation and parsing of the DNS message format (it's main purpose is to implement message compression as described in RFC 1035)
 **/
public  class ByteBuffer extends WireBuffer {

	//  Name compression (RFC 1035 4.1.4): names written so far -> their offset
	private final Map<String, Integer> lables = new HashMap<String, Integer>();

	private int rdlengthPos = 0;
	private int inc = DNS.MAXUDPLEN;

	//  DNSSEC canonical form (RFC 4034 6.2): names lower case and never compressed
	private boolean canonical = false;

	/**
	 * Write names in DNSSEC canonical form: lower case, without compression
	 * pointers (RFC 4034 6.2). Used to build the data that is signed.
	 */
	public void setCanonical(boolean on) {
		canonical = on;
	}

	public boolean isCanonical() {
		return canonical;
	}

	/**
	Default constructor (creates a ByteBuffer with the initial size set to DNS.MAXUDPLEN
	 **/
	public ByteBuffer() {
		this(new byte [DNS.MAXUDPLEN],0);
	}
	
	/**
	Create a ByteBuffer from a byte array (used mainly for receiving messages)
	 **/
	public ByteBuffer(byte [] b) {
		this(b,0);
	}
	
	/**
	 * A ByteBuffer over a byte array: reading starts at i and may go to the end of
	 * the array, writing starts at 0 (used to follow compression pointers, and to
	 * write into a given array).
	 **/
	public ByteBuffer(byte [] b, int i) {
		super(b, Math.max(0, Math.min(i, b.length)), 0, b.length);
		if( i < 0 || i > b.length ) {
			//  reading starts outside the array: every read is a format error
			pushLimit(0);
		}
	}

	/** Malformed data is a DNS format error (FORMERR). */
	@Override
	protected RuntimeException malformed(String message) {
		return new DnsFormatException(message);
	}

	/**
		Check to see if there is a pointer at the current position (a pointer is described in RFC 1035)
		@return A ByteBuffer representing the current position with pointers dereferenced
	 **/
	@Deprecated // No loop protection. Name parsing now follows pointers itself with bounds checks (see Name.init).
	public ByteBuffer chkPointer() {
		if( remaining() == 0 || (peekU8()&DNS.POINTER) == 0 ) {
			return this;
		}
		int newPos = nextShort();
		return new ByteBuffer(getBuf(),(newPos&0x3FFF));
	}
	
	/**
	Dump the ByteBuffer showing the position, hex value, binary value and character of each byte (use to debug)
	 **/
	public void dump () {
		dump(System.out);
	}
	
	/**
		Dump the ByteBuffer showing the position, hex value, binary value and character of each byte (use to debug)
	 **/
	public void dump (PrintStream out) {
		byte [] buf = getBuf();
		int rpos = getReadPos();
		int wpos = getWritePos();
		int cnt = buf.length-1;

		for(cnt=buf.length-1; cnt > 0 ; cnt-- ) {
			if( buf[cnt] != 0 ) {
				break;
			}
		}
		out.println("ByteBuffer Dump rpos="+rpos+" wpos = "+wpos+" length="+buf.length);
		out.println("cnt="+cnt);

		//  Just to make sure I save it all.
		if( cnt < buf.length ) {
			cnt++;
		}

		if( cnt < buf.length ) {
			cnt++;
		}

		int val = 0;
		char c = ' ';

		for(int i = 0; i< cnt; i++) {
			val = (buf[i]&0xff);
			if( val > 30 && val < 128 ) {
				c = (char)val;
			} else {
				c = ' ';
			}

			out.println("buf["+Utility.pad(""+i,3)+"] = "+
					" "+Utility.pad(Integer.toString(val),3)+
					" , "+Utility.pad(Integer.toHexString(val),2)+
					" , "+Utility.bi(val)+
					" , raw("+buf[i]+")"+
					" , "+c
					);
		}
		// show format rfc1035 4.1.1
		/*
                                1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		 */
		/*
		 * ID  A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.
		 */
		if( buf.length < 12 ) {
			return;
		}
		out.println("\tID\t"+Utility.makeShort(buf[0], buf[1]));
		/*
		 
			QR  A one bit field that specifies whether this message is a
                query (0), or a response (1).
		 */
		String tmp = toBinaryString(buf[2]);
		out.println("\tQR\t"+tmp.charAt(0));
		
		/*
		 OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:

                0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use
		 */
		String t2 = tmp.substring(1,5);
		int v = Integer.parseUnsignedInt(t2, 2);
		
		out.print("\tOPCODE\t"+t2+" = "+v);
		switch (v) {
		case 0: out.println(" a standard query (QUERY)"); break;
		case 1: out.println(" an inverse query (IQUERY)"); break;
		case 2: out.println(" a server status request (STATUS)"); break;
		
		default:
			out.println(" reserved for future use"); break;
			
		}
		/*
AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.

                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit
                corresponds to the name which matches the query name, or
                the first owner name in the answer section.
		 */
		out.println("\tAA\t"+tmp.charAt(5));
		
		/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
		 */
		out.println("\tTC\t"+tmp.charAt(6));
		
		/*
RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.
		 */
		out.println("\tRD\t"+tmp.charAt(7));
		
/*
 RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
 
 */
		tmp = toBinaryString(buf[3]);
		

		out.println("\tRA\t"+tmp.charAt(0));
/*
Z               Reserved for future use.  Must be zero in all queries
                and responses.
 */
		out.println("\tZ\t"+tmp.substring(1, 4)+"\tReserved for future use.  Must be zero in all queries and responses.");
		
/*
 RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone
                                transfer) for particular data.

                6-15            Reserved for future use.
 */
		t2 = tmp.substring(4);
		v = Integer.parseUnsignedInt(t2, 2);
		out.print("\tRCODE\t"+t2+" = "+v);
		switch (v) {
		case 0: out.println(" No error condition"); break;
		case 1: out.println(" Format error - The name server was unable to interpret the query."); break;
		case 2: out.println(" Server failure - The name server was\n"
				+ "                                unable to process this query due to a\n"
				+ "                                problem with the name server."); break;
		case 3: out.println(" Name Error - Meaningful only for\n"
				+ "                                responses from an authoritative name\n"
				+ "                                server, this code signifies that the\n"
				+ "                                domain name referenced in the query does\n"
				+ "                                not exist."); break;
		case 4: out.println(" Not Implemented - The name server does\n"
				+ "                                not support the requested kind of query."); break;
		case 5: out.println(" Refused - The name server refuses to\n"
				+ "                                perform the specified operation for\n"
				+ "                                policy reasons.  For example, a name\n"
				+ "                                server may not wish to provide the\n"
				+ "                                information to the particular requester,\n"
				+ "                                or a name server may not wish to perform\n"
				+ "                                a particular operation (e.g., zone\n"
				+ "                                transfer) for particular data."); break;
		
		
		default:
			out.println(" reserved for future use"); break;
			
		}
		
/*
QDCOUNT         an unsigned 16 bit integer specifying the number of
                entries in the question section.
*/
		out.println("\tQDCOUNT\t"+Utility.makeShort(buf[4], buf[5]));
/*		
ANCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the answer section.
*/
		out.println("\tANCOUNT\t"+Utility.makeShort(buf[6], buf[7]));
/*		
NSCOUNT         an unsigned 16 bit integer specifying the number of name
                server resource records in the authority records
                section.
*/
		out.println("\tNSCOUNT\t"+Utility.makeShort(buf[8], buf[9]));
/*
ARCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the additional records section.		
 */
		out.println("\tARCOUNT\t"+Utility.makeShort(buf[10], buf[11]));
	
	}
	
	private String toBinaryString(byte b) {
		String ret = Integer.toBinaryString(b);
		while(ret.length()<8) {
			ret = "0"+ret;
		}
		if( ret.length()>8) {
			ret = ret.substring(ret.length()-8);
		}
		return ret;
	}

	/**
		Get the internal byte array
	 **/
	public byte [] getBuf() {
		return array();
	}
	
	/**
		The bytes written (a copy, unless the array holds exactly them)
	 **/
	public byte [] getByteArray() {
		byte [] buf = array();
		int wpos = writePosition();
		if(wpos < buf.length) {
			return copyOf(0, wpos);
		} else {
			return buf;
		}
	}
	
	/**
		The array now grows by doubling; kept for compatibility.
	 **/
	@Deprecated
	public int getInc() { 
		return inc;
	}
	
	/**
		Get the posistion of the read pointer
	 **/
	public int getReadPos() {
		return readPosition();
	}
	
	/**
		Get the position of the write pointer
	 **/
	public int getWritePos() {
		return writePosition();
	}
	
	/**
	 * 
	 * Creation date: (9/30/2001 10:21:44 AM)
	 * @param args java.lang.String[]
	 */
	public static ByteBuffer loadFromFile(String file)
			throws Exception
	{

		BufferedReader in = new BufferedReader(new FileReader(file));
		String line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		int cnt = Integer.parseInt(line)+1;	
		int idx = 0;
		byte [] data = new byte[512];

		for(int i=0; i< cnt; i++ ) {
			line = in.readLine();
			idx = line.indexOf('=');
			line = line.substring(idx+1).trim();
			idx = line.indexOf(',');
			line = line.substring(0,idx).trim();
			data[i]=(byte)Integer.parseInt(line);	
		}

		in.close();
		ByteBuffer buf = new ByteBuffer(data);

		return buf;

	}
	/**
	 * 
	 * Creation date: (9/30/2001 10:21:44 AM)
	 * @param args java.lang.String[]
	 */
	public static String fn = "/Users/tony/test.txt";
	
	public static void main(String[] args)
			throws Exception
	{
		

		if( args.length > 0 ) {
			fn = args[0];
		}

		BufferedReader in = new BufferedReader(new FileReader(fn));
		String line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		line = in.readLine();
		int cnt = Integer.parseInt(line)+1;	
		int idx = 0;
		byte [] data = new byte[512];

		for(int i=0; i< cnt; i++ ) {
			line = in.readLine();
			idx = line.indexOf('=');
			line = line.substring(idx+1).trim();
			idx = line.indexOf(',');
			line = line.substring(0,idx).trim();
			data[i]=(byte)Integer.parseInt(line);	
			System.out.println(line);
		}

		in.close();
		ByteBuffer buf = new ByteBuffer(data);
		//buf.dump();	
		Message msg = new Message(buf);
		System.out.println("Message = "+msg);
	}
	
	public void markPos(int s){
		rdlengthPos = writePosition();
		setShort(s);
	}
	
	/**
		Get the next 8 bit byte from the ByteBuffer, incrementing the read position
		@throws DnsFormatException past the end of the message (or of a limit)
	 **/
	public int next() {
		return getU8();
	}

	/**
		Get a 32 bit int from the buffer
		@return int representation of the next four bytes in the ByteBuffer, incrementing the readPosition accordingly
	 **/
	public int nextInt() {
		return getInt32();
	}

	/**
		Get a 16 bit int from the buffer
		@return short representation of the next two bytes in the ByteBuffer, incrementing the readPosition accordingly
	 **/
	public int nextShort() {
		return getU16();
	}	
	
	//  Setters
	/**
		Add a 8 bit byte to the byte array , incrementing the write position
	 */
	public void setByte(byte b) {
		putU8(b);
	}
	
	/**
		Copy a byte array into the internal buffer at the current position
	 **/
	public void setBytes(byte [] b) {
		putBytes(b);
	}
	
	/**
		The array now grows by doubling; kept for compatibility.
	 **/
	@Deprecated
	public void setInc(int i) {
		inc = i;
	}
	
	/**
		Add a 32 bit integer to the byte array in Big Endian order (incrementing the write pointer accordingly)
	 **/
	public void setInt(int val) {
		putU32(val);
	}
	
	/**
		Add a name to this buffer, compressed as described in RFC 1035 4.1.4
		(except in canonical form). Use {@link #setName(String, boolean)} with
		false for the names of types other than RFC 1035's (RFC 3597 4).
	 **/
	public void setName(String name) {
		setName(name, true);
	}

	/**
	 * Add a name to this buffer.
	 * <p>
	 * The name is in text form (see {@link Name#wireLabels(String)}: "\\." is a dot
	 * inside a label, octets are ISO-8859-1). Labels over 63 octets and names over
	 * 255 are refused rather than written as something else (round 5 #82).
	 * Compression pointers only point below offset 0x3FFF, the most 14 bits can
	 * hold (round 5 #80).
	 *
	 * @param compress use compression pointers (never in canonical form)
	 * @throws IllegalArgumentException if the name can't be written
	 */
	public void setName(String name, boolean compress) {
		setName(name, compress, false);
	}

	/**
	 * Add a name without compression and as it is, also in canonical form: the
	 * NSEC next name keeps its case (RFC 6840 5.1).
	 */
	public void setNameAsIs(String name) {
		setName(name, false, true);
	}

	private void setName(String name, boolean compress, boolean keepCase) {
		List<byte[]> labels = Name.wireLabels(name);
		if( canonical ) {
			if( keepCase ) {
				for(byte [] b : labels) {
					putBytes8(b);
				}
				putU8(0);
				return;
			}
			for(byte [] b : labels) {
				putBytes8(asciiLower(b));
			}
			putU8(0);
			return;
		}
		for(int i=0, n=labels.size(); i < n; i++ ) {
			if( compress ) {
				String key = suffixKey(labels, i);
				Integer at = lables.get(key);
				if( at != null ) {
					setShort(at|(DNS.POINTER<<8));
					return;
				}
				if( writePosition() <= 0x3FFF ) {
					lables.put(key, writePosition());
				}
			}
			putBytes8(labels.get(i));
		}
		putU8(0);
	}

	/** The labels from i on, as a compression key (case is kept, as before). */
	private static String suffixKey(List<byte[]> labels, int i) {
		StringBuilder b = new StringBuilder();
		for(int j=i; j < labels.size(); j++ ) {
			b.append(new String(labels.get(j), java.nio.charset.StandardCharsets.ISO_8859_1)).append('\0');
		}
		return b.toString();
	}

	/** RFC 4034 6.2: only the ASCII letters are lower cased. */
	private static byte [] asciiLower(byte [] b) {
		byte [] ret = b.clone();
		for(int i=0; i < ret.length; i++ ) {
			if( ret[i] >= 'A' && ret[i] <= 'Z' ) {
				ret[i] = (byte)(ret[i]+('a'-'A'));
			}
		}
		return ret;
	}
	
	/**
		Add a name to this buffer and implement compression
		as described in RFC 1035.
	 **/
	public void setName(Name name) {
		setName(name.toString());
	}
	
	/**
		Write the rdlength into the marked location
		rdlength is calculated from the mark to the current pos
		@throws IllegalArgumentException if the rdata is over 65535 bytes
	 **/
	public void setRdLength() {
		int rdlength = writePosition()-rdlengthPos-2;
		setU16(rdlengthPos, rdlength);
	}
	
	/** Add the low 16 bits of s. */
	public void setShort(int s) {
		put16(s);
	}
	
}
