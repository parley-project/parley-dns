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
package us.bringardner.parley.dns.resolve;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Section;
import us.bringardner.parley.dns.Sshfp;

/**
 * Checks an SSH server's host key against its SSHFP records (RFC 4255, RFC 6594).
 * <p>
 * Only a DNSSEC validated answer counts (RFC 4255 2.4): without validation an
 * attacker who can spoof DNS can also publish a fingerprint for their own key. The
 * resolver must therefore be validating ({@link Resolver#isValidating()}); otherwise
 * every result is {@link Result#INSECURE}.
 * <p>
 * An SSH client uses it in its host key check, for example:
 * <pre>
 *   switch( SshfpVerifier.verify(host, keyBlob) ) {
 *     case MATCH:    accept the key;
 *     case MISMATCH:
 *     case BOGUS:    refuse (the key or DNS was tampered with);
 *     default:       fall back to known_hosts / asking the user
 *   }
 * </pre>
 * This class has no SSH dependency: the key is given in SSH wire form (the decoded
 * base64 part of an OpenSSH public key line, or what the server sent in its key
 * exchange).
 */
public final class SshfpVerifier {

	/** What the SSHFP records say about a key. */
	public enum Result {
		/** A validated record for the key's algorithm has its fingerprint. */
		MATCH,
		/** Validated records for the key's algorithm (of a usable fingerprint type) exist, but none has its fingerprint. */
		MISMATCH,
		/** Validated: no SSHFP records for the host, or none for the key's algorithm and a usable fingerprint type. */
		NO_RECORDS,
		/** The answer couldn't be validated (unsigned zone, or validation is off): proves nothing. */
		INSECURE,
		/** The answer failed validation. */
		BOGUS,
		/** No answer (servers unreachable): try again later. */
		TEMPFAIL
	}

	/** How a question is answered: the validating resolver, replaced by tests. */
	static volatile Function<Section, Resolver.Answer> resolver = q -> Resolver.resolveValidated(q, false);

	private SshfpVerifier() {
	}

	/**
	 * @param host the host name the client connected to
	 * @param keyBlob the host key in SSH wire form
	 */
	public static Result verify(String host, byte [] keyBlob) {
		int alg;
		try {
			//  a host certificate is checked by the key inside it, as OpenSSH does
			alg = Sshfp.algorithmOf(Sshfp.keyType(Sshfp.plainKey(keyBlob)));
		} catch(IllegalArgumentException ex) {
			//  a key type SSHFP can't describe (sk-* keys...)
			return Result.NO_RECORDS;
		}
		Resolver.Answer a;
		try {
			a = resolver.apply(new Section(host, DNS.SSHFP, DNS.IN));
		} catch(RuntimeException ex) {
			return Result.TEMPFAIL;
		}
		if( a == null || a.msg == null ) {
			return a != null && a.result != null && a.result.status == Validator.Status.BOGUS ? Result.BOGUS : Result.TEMPFAIL;
		}
		if( a.result == null || a.result.status == Validator.Status.INSECURE ) {
			return Result.INSECURE;
		}
		if( a.result.status == Validator.Status.BOGUS ) {
			return Result.BOGUS;
		}
		int rcode = a.msg.getResponseCode();
		if( rcode != DNS.NOERROR && rcode != DNS.NAME_ERROR ) {
			return Result.TEMPFAIL;
		}
		//  Only the records whose signatures were checked
		Validator.removeUnvalidated(a.msg, a.result);
		List<Sshfp> same = new ArrayList<Sshfp>();
		for(RR rr : a.msg.getAnswer()) {
			if( rr.getType() == DNS.SSHFP ) {
				Sshfp fp = rr instanceof Sshfp ? (Sshfp)rr : new Sshfp(rr);
				//  records of a fingerprint type this code can't compute are ignored
				if( fp.getAlgorithm() == alg && fp.isUsable() ) {
					same.add(fp);
				}
			}
		}
		if( same.isEmpty() ) {
			return Result.NO_RECORDS;
		}
		for(Sshfp fp : same) {
			if( fp.matches(keyBlob) ) {
				return Result.MATCH;
			}
		}
		return Result.MISMATCH;
	}

	/**
	 * Like {@link #verify(String, byte[])} for an OpenSSH public key line.
	 * @throws IllegalArgumentException if the line isn't an SSH public key
	 */
	public static Result verify(String host, String publicKeyLine) {
		return verify(host, Sshfp.keyBlob(publicKeyLine));
	}
}
