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

import java.net.InetAddress;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.DnsBaseClass;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Section;
import us.bringardner.parley.net.client.UpstreamHealth;

/**
 * One address of a remote (upstream) name server.
 * <p>
 * Its response time, failures, hold-off and probes are kept by parley-net's
 * {@link UpstreamHealth}, with the limits below ({@link #POLICY}).
 * <p>
 * Thread-safe: one ServerA is shared by all ResolverThreads (through the
 * Resolver's server map), so every query builds its own Message and all
 * statistics / state are atomic or volatile.
 * <p>
 * After more than MAX_TRIES consecutive failures the server is marked
 * inactive for a hold-off that starts at HOLD_OFF_MIN ms and doubles with
 * every further failure, up to DEACTIVATE ms. When the hold-off has passed
 * it gets one more try. Any answer makes it active again.
 * <p>
 * It used to be inactive for a whole hour after 3 failures: a short network
 * outage (a router restart) turned off every root server address and all
 * recursion failed for the next hour.
 */
public class ServerA  extends DnsBaseClass
{
	/** Longest hold-off (ms) for a server that keeps failing (default 10 minutes, JDns.upstreamHoldOffMax). */
	public static volatile long DEACTIVATE=10*60*1000L;
	/** First hold-off (ms) after MAX_TRIES+1 failures in a row (default 5 s, JDns.upstreamHoldOffMin). */
	public static volatile long HOLD_OFF_MIN=5*1000L;
	/** A server that is held off is probed at most this often (ms) when no server of its zone is available. */
	public static volatile long PROBE_INTERVAL=1000L;
	public static int MAX_TRIES=2;
	/** Per-attempt timeout (ms) and attempts per query sent to one upstream address */
	public static int QUERY_TIMEOUT = 2000;
	public static int QUERY_RETRY = 1;

	/** The limits above, as parley-net's UpstreamHealth reads them (changes apply at once). */
	static final UpstreamHealth.Policy POLICY = new UpstreamHealth.Policy() {
		@Override public long minHoldOff() { return HOLD_OFF_MIN; }
		@Override public long maxHoldOff() { return DEACTIVATE; }
		@Override public int maxTries() { return MAX_TRIES; }
		@Override public long probeInterval() { return PROBE_INTERVAL; }
		@Override public int queryTimeout() { return QUERY_TIMEOUT; }
		@Override public int minQueryTimeout() { return MIN_QUERY_TIMEOUT; }
	};

	//  Response time, failures, hold-off and probes (parley-net)
	private final UpstreamHealth health = new UpstreamHealth(POLICY);

	private volatile String name;
	private volatile String addrStr;
	private volatile InetAddress addr;
	private volatile int port = DNS.DNSPORT;

	/**
	 * Constructor for ServerA
	 */
	public ServerA(String n, String addr) {
		setName(n);
		if( addr != null ) {
			setAddress(addr);
		}
		//  else: a name server without glue. Its address is looked up through
		//  our own resolver when it is first queried (lookupAddress). It used
		//  to be InetAddress.getByName(name) right here: a blocking OS lookup
		//  in the resolver thread that could even query this server.
	}

	/** Most glueless name server lookups nested inside each other (per thread). */
	static final int MAX_GLUE_DEPTH = 3;
	//  Names whose address this thread is looking up (loop guard)
	private static final ThreadLocal<java.util.Set<String>> lookingUp =
			ThreadLocal.withInitial(java.util.HashSet::new);

	/**
	 * Find the address of a name server that came without glue, through the
	 * Resolver (cache, validated upstream queries). A lookup that needs itself
	 * (e.g. ns.example.com for example.com with no glue) or is nested deeper
	 * than MAX_GLUE_DEPTH gives up instead of recursing.
	 * 
	 * @return the address, or null if it can't be found
	 */
	private InetAddress lookupAddress() {
		String n = name;
		if( n == null ) {
			return null;
		}
		java.util.Set<String> busy = lookingUp.get();
		String key = n.toLowerCase();
		if( busy.contains(key) || busy.size() >= MAX_GLUE_DEPTH ) {
			return null;
		}
		busy.add(key);
		try {
			Message m = Resolver.resolve(new Section(n, DNS.A, DNS.IN));
			if( m != null ) {
				for(RR rr : m.getAnswer()) {
					if( rr instanceof A ) {
						//  From the address bytes: no DNS lookup
						InetAddress a = InetAddress.getByAddress(n, ((A)rr).getAddress());
						addrStr = a.getHostAddress();
						addr = a;
						return a;
					}
				}
			}
		} catch(Exception ex) {
			log(() -> "Could not look up name server "+n+": "+ex);
		} finally {
			busy.remove(key);
		}
		return null;
	}

	public String getName() {
		return name;
	}
	
	/**
	 * Constructor for ServerA
	 */
	public ServerA(A rr)  {
		setName( rr.getName());
		setAddress(rr.getAddressString());
	}

	/** @return this address's response time, failures and hold-off */
	public UpstreamHealth getHealth() {
		return health;
	}

	/** Average response time (ms) over all queries sent, 0 if none sent. */
	public int aveResponseTime() { 
		return health.getAverageResponseTime();
	}
	
	/** Queries sent per response received (1 == every query answered), 0 if none answered. */
	public int battingAve() { 
		int rec = health.getAnswered();
		return rec == 0 ? 0 : health.getSent() / rec; 
	}

	public int getMsgSent() {
		return health.getSent();
	}

	public int getMsgRec() {
		return health.getAnswered();
	}

	public long getLastReq() {
		return health.getLastRequest();
	}
	
	/**
	 * @return true if this server may be queried now (never deactivated, or
	 * the deactivation period has passed).
	 */
	public boolean isActive() {
		return health.isActive();
	}

	/**
	 * Send a query to this server.
	 * 
	 * @return the response, or null if the server is inactive, has no
	 * address, or did not answer.
	 */
	/** Shortest timeout used for a server whose response time is known (ms). */
	public static int MIN_QUERY_TIMEOUT = 300;

	/** Smoothed response time (ms); 0 if this server has never answered. */
	public long getSrtt() {
		return health.getSrtt();
	}

	/**
	 * Timeout for the next query: about twice the smoothed response time
	 * (MIN_QUERY_TIMEOUT..QUERY_TIMEOUT) once it is known, QUERY_TIMEOUT
	 * before that, never more than 'remaining'.
	 */
	public int timeoutFor(long remaining) {
		return health.timeoutFor(remaining);
	}

	public Message query(Section q) {
		return query(q, QUERY_TIMEOUT);
	}

	/**
	 * Send a query to this server, waiting at most timeoutMs per attempt.
	 * @return the response, or null (inactive, no address, no answer)
	 */
	public Message query(Section q, int timeoutMs) {
		return query(q, timeoutMs, 0, false);
	}

	/**
	 * Send a query to this server.
	 * 
	 * @param timeoutMs longest wait per attempt
	 * @param deadline absolute time (ms) after which the query gives up,
	 *  including a TCP retry after a truncated answer; 0 for none
	 * @param probe query even if the server is inactive, when tryProbe()
	 *  allows it (no other server of the zone is available)
	 * @return the response, or null (inactive, no address, no answer)
	 */
	public Message query(Section q, int timeoutMs, long deadline, boolean probe) {
		if( !isActive() && !(probe && health.tryProbe()) ) {
			return null;
		}

		InetAddress server = addr;
		if ( server == null ) {
			server = lookupAddress();
		}
		if ( server == null ) {
			//  Unknown address counts as a failure (deactivates after MAX_TRIES)
			health.failed();
			return null;
		}

		//  A new Message for every query. The old code shared one Message per
		//  server between all resolver threads, so one thread could send (and
		//  receive the answer to) another thread's question.
		Message qm = new Message();
		qm.setServer(server);
		qm.setPort(port);
		qm.setQuestion(q);
		qm.setTimeOut(Math.max(1, timeoutMs));
		qm.setRetry(QUERY_RETRY);
		qm.setDeadline(deadline);
		if( Resolver.isValidating() ) {
			//  Ask for the DNSSEC records (DO, RFC 3225) and, should this be a
			//  recursive server, for answers it could not validate itself (CD):
			//  we validate them
			qm.addAdditional(us.bringardner.parley.dns.Edns.newOpt(0, true));
			qm.getHeader().setCD(true);
		}

		long start = health.started();

		Message ret = null;
		try {
			ret = qm.query();
		} catch(Exception ex) {
			//  Timeout or I/O error, counted as a failure below
		}

		if( ret != null && isRefusal(ret.getResponseCode()) ) {
			//  Round 4 #62: a lame or refusing server answers fast, but not usefully: for
			//  ranking it is a failure, so it doesn't sort ahead of working servers
			health.failed(start);
		} else if( ret != null ) {
			health.succeeded(start);
		} else {
			//  A timeout counts as a slow answer so the server sorts behind responsive ones
			health.failed(start);
		}

		return ret;
	}

	/** RCODEs that mean this server can't answer the question for us (round 4 #62). */
	static boolean isRefusal(int rcode) {
		return rcode == DNS.SERVER_ERROR || rcode == DNS.REFUSED || rcode == DNS.NOT_IMPLEMENTED
				|| rcode == DNS.FORMAT_ERROR || rcode == 9;	//  9: NOTAUTH
	}

	/** Count an answer that turned out useless (e.g. a referral that isn't closer) as a failure. */
	void lame() {
		health.failed();
	}

	/** Hold-off (ms) after the k-th failure past MAX_TRIES (k >= 1): HOLD_OFF_MIN doubled k-1 times, at most DEACTIVATE. */
	static long holdOff(int k) {
		return UpstreamHealth.holdOff(POLICY, k);
	}

	/** When this server may be queried again (ms); 0 or a past time if it is active. */
	public long getInactiveUntil() {
		return health.getInactiveUntil();
	}

	/**
	 * May an inactive server be probed now? True at most once per
	 * PROBE_INTERVAL, so while every server of a zone is down each one gets
	 * one query a second from all threads together.
	 */
	boolean tryProbe() {
		return health.tryProbe();
	}

	/**
	 * Force this server active (clears the failure count) or inactive for DEACTIVATE ms.
	 */
	public void setActive(boolean newActive) {
		health.setActive(newActive);
	}

	public final void setAddress(String ip) {
		try {
			addrStr = ip;
			addr = InetAddress.getByName(ip);
		} catch(Exception ex) {
			//  This should never throw an exception since we're using the IP address			
			//  So I'll just assume for the moment that there is nothing to do here
			log("Error setting addr in SearverA ip = "+ip,ex);
		}
	}

	public InetAddress getAddress() {
		return addr;
	}

	/** UDP/TCP port of this server (default 53). */
	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}
	
	public final void setName(String n) { 
		name = n; 
	}
	
	public String toString() {
		return (name == null ? "" : name)+"("+addrStr+(port == DNS.DNSPORT ? "" : ":"+port)+") ";
	}
	
}
