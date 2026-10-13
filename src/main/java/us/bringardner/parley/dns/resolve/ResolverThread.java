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
package us.bringardner.parley.dns.resolve;

import java.io.IOException;
import java.net.*;

import us.bringardner.parley.dns.*;

/**
 * These threads do recursive resolution and prevent the server from getting backed up.
 * Creation date: (10/15/2003 5:23:16 PM)
 * @author: Tony Bringardner
 */
public class ResolverThread extends us.bringardner.parley.dns.DnsBaseClass implements Runnable 
{
	/** Queued recursive queries (was Resolver.maxBacklog, still read). */
	public static final String PROP_RESOLVER_BACKLOG = "JDns.resolverMaxBacklog";
	/** A queued query older than this (ms) is dropped instead of resolved (default 3000, 0: never). */
	public static final String PROP_RESOLVER_MAX_QUEUE_AGE = "JDns.resolverMaxQueueAge";
	/** Resolver threads are virtual threads where the JVM has them (Java 21+; default true). */
	public static final String PROP_RESOLVER_VIRTUAL_THREADS = "JDns.resolverVirtualThreads";
	/** Default for JDns.resolverMaxQueueAge: stub resolvers give up after 1 to 5 s. */
	public static final long DEFAULT_MAX_QUEUE_AGE = 3000;

	/** A queued query and when it was queued (round 4 #58). */
	private static final class Queued {
		final QueryData query;
		final long at;
		//  Queued again after waiting for the same lookup: not coalesced or aged again
		final boolean again;
		Queued(QueryData query, long at, boolean again) {
			this.query = query;
			this.at = at;
			this.again = again;
		}
	}

	//  Round 4 #70: a bounded blocking queue. SimpleObjectFIFO's notifyAll woke every
	//  resolver thread for each query.
	private static volatile java.util.concurrent.ArrayBlockingQueue<Queued> fifo;
	private static volatile long maxQueueAge = DEFAULT_MAX_QUEUE_AGE;
	private static volatile boolean virtualThreads = true;
	//  Round 4 #59: lookups in progress (see coalesceKey); later askers wait for the first
	//  (completed with true if the lookup found an answer)
	private static final java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.CompletableFuture<Boolean>> inFlight =
			new java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.CompletableFuture<Boolean>>();
	private static final java.util.concurrent.atomic.AtomicLong stale = new java.util.concurrent.atomic.AtomicLong();
	private static final java.util.concurrent.atomic.AtomicLong coalesced = new java.util.concurrent.atomic.AtomicLong();
	private volatile Thread thread;
	//  Waiting for the queue: only then does stop() interrupt (an interrupted virtual
	//  thread's socket fails at once, which would count against the upstream servers)
	private volatile boolean waiting = false;
	//  Set to false by stop() from another thread
	private volatile boolean running = false;


	private DatagramSocket sock;

	static {
		initResolverThread();
	}

	/**
	 * ResolverThread constructor comment.
	 */
	public ResolverThread() throws SocketException {
		super();
		sock = us.bringardner.parley.dns.server.UDPProsessor.getSock();
	}
	
	//  Counters for getStats()
	private static final java.util.concurrent.atomic.AtomicLong dropped = new java.util.concurrent.atomic.AtomicLong();
	private static final java.util.concurrent.atomic.AtomicLong failed = new java.util.concurrent.atomic.AtomicLong();

	/**
	 * Queue a recursive query for a resolver thread.
	 * 
	 * @return false if it could not be queued (backlog full). The caller must
	 * then answer the client itself (SERVFAIL); it used to be dropped silently
	 * and the client waited for its own timeout.
	 */
	public static boolean addQuery(QueryData query) {
		return enqueue(new Queued(query, System.currentTimeMillis(), false));
	}

	private static boolean enqueue(Queued q) {
		boolean ret = q.query != null && fifo.offer(q);
		if( !ret ) {
			dropped.incrementAndGet();
		}
		return ret;
	}

	/** How often backlogFullWarning() returns a message. */
	static final long FULL_WARNING_INTERVAL_MS = 10_000;
	private static final java.util.concurrent.atomic.AtomicLong lastFullWarning = new java.util.concurrent.atomic.AtomicLong();
	private static final java.util.concurrent.atomic.AtomicLong droppedAtLastWarning = new java.util.concurrent.atomic.AtomicLong();

	/**
	 * Call after addQuery returned false. Returns a message to log at most
	 * once every 10 seconds (with the number of queries turned away since the
	 * last one), otherwise null. Under overload the server used to log an
	 * error for every query it could not queue.
	 */
	/** Test hook: the next backlogFullWarning() returns a message. */
	static void resetBacklogWarning() {
		lastFullWarning.set(0);
	}

	public static String backlogFullWarning() {
		long now = System.currentTimeMillis();
		long last = lastFullWarning.get();
		if( now - last < FULL_WARNING_INTERVAL_MS || !lastFullWarning.compareAndSet(last, now) ) {
			return null;
		}
		long total = dropped.get();
		long since = total - droppedAtLastWarning.getAndSet(total);
		return "Resolver backlog full (capacity "+getMaxBackLog()+", "+PROP_RESOLVER_BACKLOG+"): "
				+since+" queries answered without recursion since the last warning, "+total+" in total";
	}

	/** Discard all queued queries. @return how many were removed */
	public static int clearBacklog() {
		return fifo.drainTo(new java.util.ArrayList<Queued>());
	}

	/** Queued queries dropped because they waited longer than JDns.resolverMaxQueueAge (round 4 #58). */
	public static long getStale() {
		return stale.get();
	}

	/** Queries that waited for the same lookup in progress instead of starting their own (round 4 #59). */
	public static long getCoalesced() {
		return coalesced.get();
	}

	/** @param ms a queued query older than this is dropped; 0 or less: never */
	public static void setMaxQueueAge(long ms) {
		maxQueueAge = ms;
	}

	public static long getMaxQueueAge() {
		return maxQueueAge;
	}

	/** @param on resolver threads started from now on are virtual threads (Java 21+) */
	public static void setVirtualThreads(boolean on) {
		virtualThreads = on;
	}

	public static boolean isVirtualThreads() {
		return virtualThreads;
	}

	/** Queries refused because the backlog was full. */
	public static long getDropped() {
		return dropped.get();
	}

	/** Queries answered with SERVFAIL because resolution failed or threw. */
	public static long getFailed() {
		return failed.get();
	}

	/**
	 * One response for a CNAME chain from our zones that points outside them:
	 * the question and CNAME records of 'partial' followed by the records
	 * resolved for the target. The RCODE is the target's (RFC 6604); AA is off
	 * because part of the answer is not ours. If the target could not be
	 * resolved (resolved == null) the chain is returned with SERVFAIL.
	 */
	public static Message completeCnameAnswer(Message partial, Message resolved) {
		Message ret = new Message();
		us.bringardner.parley.dns.Header h = partial.getHeader().copy();
		h.setAA(false);
		h.setTC(false);
		h.setRA(true);
		ret.setHeader(h);
		ret.setMessageTypeResponse();
		for(Section q : partial.getQuestion()) {
			ret.addQuestion(new Section(q));
		}
		for(RR rr : partial.getAnswer()) {
			ret.addAnswer(rr);
		}
		if( resolved == null ) {
			ret.setResponseCode(DNS.SERVER_ERROR);
			return ret;
		}
		for(RR rr : resolved.getAnswer()) {
			ret.addAnswer(rr);
		}
		for(RR rr : resolved.getAuthority()) {
			ret.addAuthority(rr);
		}
		for(RR rr : resolved.getAdditional()) {
			ret.addAdditional(rr);
		}
		ret.setResponseCode(resolved.getResponseCode());
		return ret;
	}

	/**
	 * A response to 'query' with no data and the given RCODE (e.g. SERVFAIL):
	 * same ID, opcode, RD and question as the request, QR=1, RA=1, AA=0.
	 */
	public static Message failure(QueryData query, int rcode) {
		Message req = query.getMessage();
		Message ret = new Message();
		us.bringardner.parley.dns.Header h = req.getHeader().copy();
		h.setAA(false);
		h.setTC(false);
		h.setRA(true);
		ret.setHeader(h);
		ret.setMessageTypeResponse();
		ret.setResponseCode(rcode);
		//  The question as the client sent it (QueryData's may have followed a CNAME)
		Section q = req.getFirstQuestion() != null ? req.getFirstQuestion() : query.getQuestion();
		if( q != null ) {
			ret.setQuestion(new Section(q));
		}
		return ret;
	}
	
	private static final java.util.concurrent.atomic.AtomicLong bogus = new java.util.concurrent.atomic.AtomicLong();

	/** Answers that failed DNSSEC validation (the clients got SERVFAIL). */
	public static long getBogus() {
		return bogus.get();
	}

	/**
	 * Resolve for a client, validating unless it set CD. An answer that
	 * fails validation (BOGUS) is dropped: the Answer's msg is null, so the
	 * client gets SERVFAIL (RFC 4035 5.5).
	 */
	public static Resolver.Answer resolveFor(QueryData query, Section toResolve) {
		Resolver.Answer a = Resolver.resolveValidated(toResolve, query.getMessage().getHeader().getCD());
		if( a.result != null && a.result.status == Validator.Status.BOGUS ) {
			bogus.incrementAndGet();
			new ResolverThread0().log("DNSSEC validation failed for "+toResolve+": "+a.result.why);
			return new Resolver.Answer(null, a.result);
		}
		return a;
	}

	/**
	 * The answer for a recursive query from the cache alone (no network), or
	 * null if a resolver thread is needed. Used by the UDP processor so that
	 * cached names are answered at once instead of waiting in the resolver
	 * queue behind slow lookups (with 10 threads busy on names that time out,
	 * the queue filled and cached names got SERVFAIL too).
	 */
	public static Resolver.Answer cachedFor(QueryData query, Section toResolve) {
		return Resolver.resolveCached(toResolve, query.getMessage().getHeader().getCD());
	}

	//  Only for logging from static code
	private static final class ResolverThread0 extends us.bringardner.parley.dns.DnsBaseClass {
	}

	/**
	 * Shape a recursive answer for the client that asked (RFC 4035 3.2):
	 * AD set only for a validated (SECURE) answer to a client that set DO or
	 * AD; CD echoed; without DO the DNSSEC records (RRSIG, NSEC, NSEC3) are
	 * removed unless they were asked for.
	 * 
	 * @param partial part of the answer came from our own zones (AD is not set)
	 */
	public static void finish(Message msg, QueryData query, Validator.Result result, boolean partial) {
		if( msg == null ) {
			return;
		}
		Message req = query.getMessage();
		boolean dnssecOk = query.getEdns().isDnssecOk();
		boolean secure = result != null && result.status == Validator.Status.SECURE && !partial;
		//  A recursive answer (often from the cache): not authoritative,
		//  recursion available, RD as the client sent it. The upstream
		//  server's header used to be passed on (AA=1, RA=0, RD=0).
		msg.getHeader().setAA(false);
		msg.getHeader().setRA(true);
		msg.getHeader().setRD(req.getHeader().getRD());
		if( secure ) {
			//  Only what was validated goes out with a SECURE answer (round 5 #83)
			Validator.removeUnvalidated(msg, result);
		}
		msg.getHeader().setAD(secure && (dnssecOk || req.getHeader().getAD()));
		msg.getHeader().setCD(req.getHeader().getCD());
		if( !dnssecOk ) {
			Section q = req.getFirstQuestion();
			int qtype = q == null ? 0 : q.getType();
			for(java.util.List<RR> section : java.util.Arrays.asList(msg.getAnswer(), msg.getAuthority(), msg.getAdditional())) {
				section.removeIf(rr -> {
					int t = rr.getType();
					return (t == DNS.RRSIG || t == DNS.NSEC || t == DNS.NSEC3) && t != qtype;
				});
			}
		}
	}

	public static int backlog() {
		return fifo.size();
	}
	
	public static int getBacklog() {
		return fifo.size();
	}
	
	public static int getMaxBackLog() {
		java.util.concurrent.ArrayBlockingQueue<Queued> q = fifo;
		return q.size()+q.remainingCapacity();
	}
	
	/**
	 * Default for JDns.resolverMaxBacklog. It was 20: a short burst of cache
	 * misses (e.g. a page load that looks up 30 names) already overflowed it.
	 */
	public static final int DEFAULT_MAX_BACKLOG = 200;

	private static void initResolverThread() {
		int maxBacklog = DEFAULT_MAX_BACKLOG;

		String tmp = us.bringardner.parley.core.util.RenamedProperty.get(PROP_RESOLVER_BACKLOG, "Resolver.maxBacklog");

		if( tmp != null ) {
			try {
				maxBacklog = Integer.parseInt(tmp);
			} catch(Exception ex) {}
		}

		fifo = new java.util.concurrent.ArrayBlockingQueue<Queued>(Math.max(1, maxBacklog));
	}
	
	/** Nothing to do: the queue wakes one thread per query. */
	@Deprecated
	public static void notifyThreads() {
	}
	
	/**
	 * When an object implementing interface <code>Runnable</code> is used 
	 * to create a thread, starting the thread causes the object's 
	 * <code>run</code> method to be called in that separately executing 
	 * thread. 
	 * <p>
	 * The general contract of the method <code>run</code> is that it may 
	 * take any action whatsoever.
	 *
	 * @see     java.lang.Thread#run()
	 */
	public void run() {
		//  'running' is set by start(): setting it here raced with stop() and
		//  a thread stopped right after starting would run forever.
		while( running ) {
			try {
				setState("Waiting on fifo");
				waiting = true;
				if( !running ) {
					break;
				}
				Queued q;
				try {
					q = fifo.take();
				} finally {
					waiting = false;
					if( running ) {
						//  an interrupt that came just as the wait ended
						Thread.interrupted();
					}
				}
				setState("Returned on fifo");
				if( running ) {
					serve(q);
				}
			} catch(InterruptedException ex) {
				//  stop() interrupts the wait on the queue
				if( !running ) {
					break;
				}
			} catch(Exception ex) {
				logError("Unexpected error in resolver thread", ex);
			}
		}

		setState("Stopped");
		running = false;
	}

	/**
	 * The lookup a query needs: its name, type and class, and whether the client
	 * set CD (validation). Queries with the same key get the same upstream answer.
	 */
	static String coalesceKey(Section toResolve, boolean cd) {
		return us.bringardner.parley.dns.dnssec.Canonical.key(toResolve.getName())+"|"+toResolve.getType()+"|"+toResolve.getDnsClass()+"|"+cd;
	}

	/**
	 * Resolve a queued query and answer it. If the same lookup is in progress, the
	 * query waits for it (without holding this thread) and is answered from the cache
	 * it fills; a query that already waited once resolves on its own.
	 */
	private void serve(Queued q) {
		QueryData question = q.query;
		boolean coalesce = !q.again;
		long age = System.currentTimeMillis()-q.at;
		long maxAge = maxQueueAge;
		if( coalesce && maxAge > 0 && age > maxAge ) {
			//  Round 4 #58: the client gave up long ago; resolving it only delays the rest
			stale.incrementAndGet();
			return;
		}
		Section toResolve = question.getResolveQuestion();
		boolean cd = question.getMessage().getHeader().getCD();
		String key = coalesceKey(toResolve, cd);
		java.util.concurrent.CompletableFuture<Boolean> mine = new java.util.concurrent.CompletableFuture<Boolean>();
		java.util.concurrent.CompletableFuture<Boolean> first = coalesce ? inFlight.putIfAbsent(key, mine) : null;
		if( first != null ) {
			//  Round 4 #59: the same lookup is in progress; answer when it is done
			coalesced.incrementAndGet();
			first.whenComplete((found, ex) -> afterLookup(q, Boolean.TRUE.equals(found)));
			return;
		}
		boolean found = false;
		try {
			setState("Call Resolver", question);
			Message msg = null;
			Validator.Result validated = null;
			try {
				Resolver.Answer a = resolveFor(question, toResolve);
				msg = a.msg;
				validated = a.result;
			} catch(RuntimeException | StackOverflowError ex) {
				logError("Resolver failed for "+toResolve, ex);
			}
			setState("Returned from resolver");
			found = msg != null;
			respond(question, msg, validated);
		} finally {
			if( coalesce ) {
				inFlight.remove(key, mine);
			}
			mine.complete(found);
		}
	}

	/**
	 * A query that waited for the same lookup: answered from the cache at once if the
	 * lookup filled it, else queued again (it then resolves on its own).
	 */
	private void afterLookup(Queued q, boolean found) {
		try {
			QueryData question = q.query;
			if( !found ) {
				//  The lookup failed (or was BOGUS): the same answer, SERVFAIL (or the
				//  CNAME chain without its target), rather than another failing lookup
				respond(question, null, null);
				return;
			}
			Section toResolve = question.getResolveQuestion();
			Resolver.Answer a = cachedFor(question, toResolve);
			if( a != null && a.msg != null ) {
				respond(question, a.msg, a.result);
				return;
			}
			//  Found but not cached (e.g. TTL 0): resolve it on its own
			if( !enqueue(new Queued(question, q.at, true)) ) {
				respond(question, null, null);
			}
		} catch(RuntimeException ex) {
			logError("Unexpected error answering a coalesced query", ex);
		}
	}

	/** Answer the client: the resolved message, a completed CNAME chain, or SERVFAIL. */
	private void respond(QueryData question, Message msg, Validator.Result validated) {
		Message partial = question.getPartialAnswer();
		if( partial != null ) {
			//  Complete a local CNAME chain that pointed outside our zones
			if( msg == null ) {
				failed.incrementAndGet();
			}
			msg = completeCnameAnswer(partial, msg);
		} else if( msg == null ) {
			//  No answer (all servers timed out, no servers, or an error):
			//  tell the client instead of leaving it to time out.
			failed.incrementAndGet();
			msg = failure(question, DNS.SERVER_ERROR);
		}
		finish(msg, question, validated, partial != null);
		sendResponse(msg,question);
	}
	
	/**
	 * 
	 * Creation date: (8/26/2001 10:41:48 AM)
	 * @param msg JDns.Message
	 */
	public void sendResponse(Message msg, QueryData query) {

		setState("SendResponse Begin");
		if( msg != null && query.getPort() != -1) {

			//  Just in case;
			msg.setID(query.getMessage().getID());

			//  The old code cut the byte array at MAXUDPLEN (a corrupt packet
			//  ending mid-record) and set TC on the shared message.
			//  EDNS: drop an upstream OPT, echo ours if the client sent one
			us.bringardner.parley.dns.Edns.applyToResponse(msg, query.getEdns());
			byte [] data = msg.toByteArray(us.bringardner.parley.dns.server.UDPProsessor.udpLimit(query.getEdns()));
			int dataSize = data.length;

			setState("SendResponse getPacket");
			DatagramPacket pckt = new DatagramPacket(data,dataSize,query.getClient(),query.getPort());

			setState("SendResponse gotPacket");
			try {
				setState("SendResponse before sock.send");

				sock.send(pckt);
				setState("SendResponse after sock.send");	

			} catch(IOException ex) {
				log("IOException sending reply",ex);
				setState("SendResponse IOError");
			}
		}
		setState("SendResponse End");
	}
	
	public synchronized void start(String name) {
		if( !running ) {
			running = true;
			thread = new us.bringardner.parley.core.NamedThreadFactory(name).virtual(virtualThreads).newThread(this);
			thread.start();
			setState("Started");
		}
	}
	
	/**
	 * Stop after the current query (a lookup in progress is finished and answered); a
	 * thread waiting for a query stops at once.
	 */
	public void stop() {
		running = false;
		Thread t = thread;
		if( t != null && waiting ) {
			t.interrupt();
		}
	}

	/** Wait up to ms for this resolver thread to finish. @return true if it has */
	public boolean join(long ms) throws InterruptedException {
		Thread t = thread;
		if( t != null ) {
			t.join(ms);
			return !t.isAlive();
		}
		return true;
	}
	
}
