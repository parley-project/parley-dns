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
 */
package us.bringardner.parley.dns;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import us.bringardner.parley.core.util.Hex;

/**
 * The DNS SSHFP resource record (RFC 4255, RFC 6594, RFC 7479): the fingerprint of
 * an SSH host key, so a client can check a server's key without asking the user.
 * The record only proves anything when its answer is DNSSEC validated
 * (see {@link us.bringardner.parley.dns.resolve.SshfpVerifier}).
 * <p>
 * Text form: algorithm, fingerprint type, fingerprint in hex, e.g.
 * <code>host.example. IN SSHFP 4 2 0123...</code>
 */
public class Sshfp extends RR {

	/** Key algorithms (RFC 4255, 6594, 7479, 8709). */
	public static final int RSA = 1;
	public static final int DSA = 2;
	public static final int ECDSA = 3;
	public static final int ED25519 = 4;
	public static final int ED448 = 6;

	/** Fingerprint types. */
	public static final int SHA1 = 1;
	public static final int SHA256 = 2;

	private int algorithm;
	private int fingerprintType;
	private byte [] fingerprint = new byte[0];

	public Sshfp() {
		super();
		setType(SSHFP);
		setDnsClass(IN);
		isBase = false;
		dirty = true;
	}

	public Sshfp(String name) {
		this(name, IN);
	}

	public Sshfp(String name, int dnsClass) {
		super(name,SSHFP,dnsClass);
		isBase = false;
		dirty = true;
	}

	/** An SSHFP record from a generic record read from the wire. */
	public Sshfp(RR rr) {
		super(rr);
		//  The field initializers ran after super() had parsed the rdata
		setFromRdata();
		isBase = false;
	}

	/**
	 * The record for an SSH public key.
	 *
	 * @param name the host name
	 * @param keyBlob the key in SSH wire form (the base64 part of an OpenSSH .pub line, decoded)
	 * @param fingerprintType {@link #SHA256} (or {@link #SHA1}, deprecated)
	 * @throws IllegalArgumentException for a key type SSHFP has no number for
	 */
	public static Sshfp forKey(String name, byte [] keyBlob, int fingerprintType) {
		Sshfp ret = new Sshfp(name);
		ret.setAlgorithm(algorithmOf(keyType(keyBlob)));
		ret.setFingerprintType(fingerprintType);
		ret.setFingerprint(fingerprint(keyBlob, fingerprintType));
		return ret;
	}

	/**
	 * The record for one line of an OpenSSH public key file
	 * ("ssh-ed25519 AAAA... comment").
	 */
	public static Sshfp forPublicKeyLine(String name, String line, int fingerprintType) {
		return forKey(name, keyBlob(line), fingerprintType);
	}

	/** @return the key blob of an OpenSSH public key line ("type base64 [comment]") */
	public static byte [] keyBlob(String line) {
		String [] f = line.trim().split("\\s+");
		if( f.length < 2 ) {
			throw new IllegalArgumentException("Not an SSH public key: "+line);
		}
		byte [] blob = Base64.getDecoder().decode(f[1]);
		String type = keyType(blob);
		if( !type.equals(f[0]) ) {
			throw new IllegalArgumentException("The key is "+type+", the line says "+f[0]);
		}
		return blob;
	}

	/**
	 * @return the key type at the start of a key blob (an SSH string: 4 byte length,
	 *  then ASCII), e.g. ssh-ed25519
	 */
	public static String keyType(byte [] blob) {
		if( blob == null || blob.length < 4 ) {
			throw new IllegalArgumentException("Not an SSH key");
		}
		long len = ((blob[0]&0xffL) << 24) | ((blob[1]&0xff) << 16) | ((blob[2]&0xff) << 8) | (blob[3]&0xff);
		if( len < 1 || len > 64 || 4+len > blob.length ) {
			throw new IllegalArgumentException("Not an SSH key");
		}
		return new String(blob, 4, (int)len, java.nio.charset.StandardCharsets.US_ASCII);
	}

	/**
	 * @param keyType an SSH key type (ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256...)
	 * @return its SSHFP algorithm number
	 * @throws IllegalArgumentException if SSHFP has none for it
	 */
	public static int algorithmOf(String keyType) {
		switch(keyType) {
		case "ssh-rsa": return RSA;
		case "ssh-dss": return DSA;
		case "ecdsa-sha2-nistp256":
		case "ecdsa-sha2-nistp384":
		case "ecdsa-sha2-nistp521": return ECDSA;
		case "ssh-ed25519": return ED25519;
		case "ssh-ed448": return ED448;
		default: throw new IllegalArgumentException("SSHFP has no algorithm for "+keyType);
		}
	}

	/** @return the fingerprint of a key blob: SHA-1 or SHA-256 of the blob */
	public static byte [] fingerprint(byte [] keyBlob, int fingerprintType) {
		String alg;
		switch(fingerprintType) {
		case SHA1: alg = "SHA-1"; break;
		case SHA256: alg = "SHA-256"; break;
		default: throw new IllegalArgumentException("Unknown SSHFP fingerprint type "+fingerprintType);
		}
		try {
			return MessageDigest.getInstance(alg).digest(keyBlob);
		} catch(NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
	}

	/**
	 * @return true if this record is for this key: same algorithm, and the
	 *  fingerprint of the key matches (a fingerprint type this code doesn't know never
	 *  matches)
	 */
	public boolean matches(byte [] keyBlob) {
		try {
			byte [] key = plainKey(keyBlob);
			if( !isUsable() || algorithmOf(keyType(key)) != algorithm ) {
				return false;
			}
			return MessageDigest.isEqual(fingerprint(key, fingerprintType), fingerprint);
		} catch(IllegalArgumentException ex) {
			return false;
		}
	}

	/**
	 * @return true if this record can be checked: a fingerprint type this code knows,
	 *  with a fingerprint of that type's length (a record of another type is ignored,
	 *  as OpenSSH does)
	 */
	public boolean isUsable() {
		return (fingerprintType == SHA1 && fingerprint.length == 20) || (fingerprintType == SHA256 && fingerprint.length == 32);
	}

	/**
	 * The key a fingerprint is made of: for an OpenSSH host certificate
	 * (ssh-ed25519-cert-v01@openssh.com...) the plain key inside it, as OpenSSH checks
	 * it; any other key as it is.
	 *
	 * @throws IllegalArgumentException for a malformed certificate
	 */
	public static byte [] plainKey(byte [] keyBlob) {
		String type = keyType(keyBlob);
		String suffix = "-cert-v01@openssh.com";
		if( !type.endsWith(suffix) ) {
			return keyBlob;
		}
		String plain = type.substring(0, type.length()-suffix.length());
		int fields;
		switch(plain) {
		case "ssh-rsa": fields = 2; break;		//  e, n
		case "ssh-dss": fields = 4; break;		//  p, q, g, y
		case "ecdsa-sha2-nistp256":
		case "ecdsa-sha2-nistp384":
		case "ecdsa-sha2-nistp521": fields = 2; break;	//  curve, Q
		case "ssh-ed25519": fields = 1; break;	//  pk
		case "ssh-ed448": fields = 1; break;
		default: return keyBlob;
		}
		//  type, nonce, then the key's own fields (each an SSH string or mpint)
		int pos = 0;
		pos = skipString(keyBlob, pos);
		pos = skipString(keyBlob, pos);
		int start = pos;
		for(int i=0; i < fields; i++ ) {
			pos = skipString(keyBlob, pos);
		}
		byte [] t = plain.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
		byte [] ret = new byte[4+t.length+(pos-start)];
		ret[0] = (byte)(t.length >> 24);
		ret[1] = (byte)(t.length >> 16);
		ret[2] = (byte)(t.length >> 8);
		ret[3] = (byte)t.length;
		System.arraycopy(t, 0, ret, 4, t.length);
		System.arraycopy(keyBlob, start, ret, 4+t.length, pos-start);
		return ret;
	}

	private static int skipString(byte [] b, int pos) {
		if( pos+4 > b.length ) {
			throw new IllegalArgumentException("Malformed SSH certificate");
		}
		long len = ((b[pos]&0xffL) << 24) | ((b[pos+1]&0xff) << 16) | ((b[pos+2]&0xff) << 8) | (b[pos+3]&0xff);
		if( len > b.length-pos-4 ) {
			throw new IllegalArgumentException("Malformed SSH certificate");
		}
		return pos+4+(int)len;
	}

	@Override
	public RR copy() {
		Sshfp ret = new Sshfp();
		super.copy(ret);
		ret.algorithm = algorithm;
		ret.fingerprintType = fingerprintType;
		ret.fingerprint = fingerprint;
		return ret;
	}

	public int getAlgorithm() { return algorithm; }
	public int getFingerprintType() { return fingerprintType; }
	public byte [] getFingerprint() { return fingerprint.clone(); }

	public void setAlgorithm(int algorithm) {
		if( algorithm < 0 || algorithm > 255 ) {
			throw new IllegalArgumentException("SSHFP algorithm must be 0-255: "+algorithm);
		}
		this.algorithm = algorithm;
		dirty = true;
	}

	public void setFingerprintType(int type) {
		if( type < 0 || type > 255 ) {
			throw new IllegalArgumentException("SSHFP fingerprint type must be 0-255: "+type);
		}
		this.fingerprintType = type;
		dirty = true;
	}

	public void setFingerprint(byte [] fp) {
		this.fingerprint = fp == null ? new byte[0] : fp.clone();
		dirty = true;
	}

	/** @param hex the fingerprint in hex (as in a zone file; may be split in parts) */
	public void setFingerprint(String hex) {
		setFingerprint(Hex.decode(hex.replaceAll("\\s", "")));
	}

	@Override
	public void setFromRdata() {
		byte [] r = rdata;
		if( r == null || r.length < 2 ) {
			throw new DnsFormatException("Invalid SSHFP rdata");
		}
		algorithm = r[0]&0xff;
		fingerprintType = r[1]&0xff;
		fingerprint = Arrays.copyOfRange(r, 2, r.length);
		dirty = false;
	}

	@Override
	public void toByteArray(ByteBuffer out) {
		super.toByteArray(out);
		out.setByte((byte)algorithm);
		out.setByte((byte)fingerprintType);
		out.setBytes(fingerprint);
		out.setRdLength();
	}

	@Override
	public String getRdataAsString() {
		return algorithm+" "+fingerprintType+" "+Hex.encode(fingerprint);
	}

	@Override
	public String toString() {
		return super.toString()+" algorithm="+algorithm+" type="+fingerprintType+" fingerprint="+Hex.encode(fingerprint);
	}
}
