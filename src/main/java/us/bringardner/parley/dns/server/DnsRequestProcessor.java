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
package us.bringardner.parley.dns.server;

import java.util.*;

import us.bringardner.parley.dns.*;
import us.bringardner.parley.dns.resolve.QueryData;
/**
 * 
 * Creation date: (8/26/2001 7:01:49 AM)
 * @author: Tony Bringardner
 */
public abstract class DnsRequestProcessor  extends DnsBaseClass implements DNS
{
	DnsServer server;
	//  EDNS of the request being processed (process() runs one at a time per processor)
	protected Edns.Request currentEdns = Edns.Request.NONE;
	//  TSIG of the request being processed (null if it was not signed): sendResponse signs with it
	protected volatile Tsig.Session currentTsig;
/**
 * Process an incoming request (Search for the query then call sendResponse).
 **/
 public void process(QueryData query) {
	//  No OutOfMemoryError handling here any more: the old code trimmed the
	//  cache, retried, and finally called System.exit(1) from this thread.
	//  Caches are bounded now; a JVM error propagates to FatalErrorHandler.
	setState("Processing Message begin");
	Edns.Request edns = query.getEdns();
	currentEdns = edns;
	currentTsig = null;
	Tsig.Session tsig;
	try {
		//  Round 5 #85: a signed UPDATE or zone transfer is accepted once. Other
		//  requests are read-only and clients resend them unchanged on a timeout.
		tsig = Tsig.Session.verifyRequest(server.getTsigKeys(), query.getWire(), server.getTsigFudge(),
				needsReplayCheck(query.getMessage()) ? server.getTsigReplays() : null);
	} catch(DnsFormatException ex) {
		//  A TSIG that is not the last record, or a malformed one
		sendResponse(Edns.formatError(query.getMessage()));
		return;
	}
	if( tsig != null ) {
		currentTsig = tsig;
		if( tsig.isRepeat() && query.getMessage().getHeader().getOPCODE() == DNS.UPDATE ) {
			//  Round 5 #85: the same signed UPDATE again, e.g. resent because the
			//  response was lost. It gets the first answer again; nothing is applied
			//  a second time, so a replay can't change the zone either.
			int first = tsig.getReplay().getResult();
			if( first >= 0 ) {
				currentTsig = tsig.asFirst();
				sendResponse(repeatedAnswer(query.getMessage(), first));
			}
			//  else the first copy is still being processed: its answer is on the way
			currentTsig = null;
			return;
		}
		if( tsig.getError() != Tsig.NOERROR ) {
			//  RFC 8945 5.2: NOTAUTH, with the TSIG error in the (unsigned or,
			//  for BADTIME, signed) TSIG of the response
			final int err = tsig.getError();
			log(() -> "TSIG error "+err+" for a request from "+query.getClient());
			sendResponse(notAuth(query.getMessage()));
			currentTsig = null;
			return;
		}
		query.setTsigKey(tsig.getKey().getName());
		query.setTsigSession(tsig);
	}
	try {
		answer(query, edns);
	} finally {
		currentTsig = null;
	}
	setState("Processing Message Complete");
 }

 /** UPDATEs and zone transfers change or reveal a whole zone: their signed requests are used once. */
 static boolean needsReplayCheck(Message req) {
	if( req.getHeader().getOPCODE() == DNS.UPDATE ) {
		return true;
	}
	Section q = req.getFirstQuestion();
	return q != null && (q.getType() == DNS.AXFR || q.getType() == DNS.IXFR);
 }

 /** Note the RCODE of the answer to a signed request, for a repeat of it (see process). */
 private Message remember(Message m) {
	Tsig.Session t = currentTsig;
	if( t != null && t.getReplay() != null && m != null ) {
		t.getReplay().setResult(m.getResponseCode());
	}
	return m;
 }

 /** The answer to a repeated UPDATE: its zone section and the first answer's RCODE. */
 static Message repeatedAnswer(Message req, int rcode) {
	Message ret = notAuth(req);
	ret.getHeader().setRCODE(rcode);
	return ret;
 }

 /** A NOTAUTH response to a request (its question, no records). */
 static Message notAuth(Message req) {
	Message ret = new Message();
	Header h = req.getHeader().copy();
	ret.setHeader(h);
	ret.setMessageTypeResponse();
	for(Section s : req.getQuestion()) {
		ret.setQuestion(s);
	}
	ret.getHeader().setRCODE(Tsig.NOTAUTH);
	return ret;
 }

 private void answer(QueryData query, Edns.Request edns) {
	if( edns.isMalformed() ) {
		//  RFC 6891 6.1.1: more than one OPT (or a bad one) is FORMERR
		sendResponse(remember(Edns.formatError(query.getMessage())));
	} else if( edns.isBadVersion() ) {
		sendResponse(remember(Edns.badVersion(query.getMessage())));
	} else {
		List<Message> reply = server.query(query);
		if( reply != null ) {
			Tsig.Session t = currentTsig;
			if( t != null && t.getReplay() != null && !reply.isEmpty() ) {
				//  remembered for a repeat of this request (see process)
				t.getReplay().setResult(reply.get(0).getResponseCode());
			}
			for(Message m : reply) {
				Edns.applyToResponse(m, edns);
				sendResponse(m);
			}
		}
	}
 }
/**
 * Insert the method's description here.
 * Creation date: (8/26/2001 7:03:38 AM)
 * @param msg parley.dns.Message
 */
public abstract void sendResponse(Message msg);
}
