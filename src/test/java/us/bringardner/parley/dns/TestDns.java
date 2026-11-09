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
 * ~version~V000.01.04-V000.01.02-V000.00.05-V000.00.01-V000.00.00-
 */
package us.bringardner.parley.dns;


import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import us.bringardner.parley.dns.server.DnsServer;
import us.bringardner.parley.dns.util.NsLookup;

public class TestDns implements DNS {

	static class NsLookupTestData {
		String promt;
		String cmd;
		String response;
		
		@Override
		public boolean equals(Object obj) {
			boolean ret = false;
			if (obj instanceof NsLookupTestData) {
				NsLookupTestData other = (NsLookupTestData) obj;
				ret = cmd.equals(other.cmd) 
						&& response.equals(other.response)
						;
			}
			
			return ret;
		}
		
		@Override
		public String toString() {
			return ""+cmd+"\n"+response;
		}
	}




	private int testQCodes[] = {A,NS,MX,CNAME,SOA,MB,MG,MR,WKS,PTR,HINFO,MINFO,TXT};

	Map<String,String> expected = new HashMap<String, String>();
	private static DnsServer server;

	private static String localServerAddress;

	private static int localServrPort;



	@BeforeAll
	public static void setUp() throws Exception {

		System.setProperty(DnsServer.PROP_DNS_PROPERTIES, Fixtures.file("TestFiles/TestDns.properties").getPath());
		//  System properties win over the properties file: point the server at the fixtures on the class path
		System.setProperty(DnsServer.PROP_DNS_DIR, Fixtures.file("TestFiles").getPath());
		System.setProperty(DnsServer.PROP_ZONE_DIR, Fixtures.file("TestFiles/zones").getPath());
		System.setProperty("parley.log.level","ERROR");
		server = new DnsServer();
		server.setRecursionAvailable(false);
		server.start();
		//  Throws (failing this class only) if the server can't start.
		server.awaitStarted(60_000);


		Assertions.assertTrue(server.isRunning(),"DNS Server is not running");
		localServrPort = DNS.DNSPORT;
		localServerAddress = null;

		String tmp = null;
		if(( tmp = server.getProperty(DnsServer.PROP_BIND_ADDRESS)) != null ) {
			localServerAddress = tmp;
		}

		if(( tmp = server.getProperty(DnsServer.PROP_PORT)) != null ) {
			localServrPort = Integer.parseInt(tmp);
		}


	}

	@AfterAll
	public static void tearDown() throws Exception {
		if( server != null ) {
			//  stop() leaves the JVM wide shutdown flag set, which stopped the
			//  UDP/TCP processors of tests that ran after this one.
			server.stopAndWait(10_000);
			DnsServer.setShutdown(false);
		}
	}



	int count(String str) {
		int ret = 0;
		byte [] data = str.getBytes();
		for (int idx = 0; idx < data.length; idx++) {
			if( data[idx] == (byte)':') {
				ret++;
			}
		}
		if( !str.endsWith(":") ) {
			ret++;
		}
		return ret;
	}


	/** Needs the real root servers (UDP and TCP port 53): run with -DliveTests=true. */
	@Test
	@EnabledIfSystemProperty(named = "liveTests", matches = "true")
	public void testRootServers() throws Exception {
		runTests(NsLookup.getDnsServer(), DNS.DNSPORT,"google.com","irs.gov");
	}

	@Test
	public void testServers() throws Exception {
		if( server.isRunning()) {
		runTests(REFUSED_RCODE, localServerAddress, localServrPort,"foo.com","bar.com");
		}
	}



	//  (testDomain added a domain to the old in-memory common list and removed it again. The
	//  list comes from parley.dns.domainList now, and the listed domains are served from the
	//  shared zone: TestListedDomains.)

	private void assertEquals(String string, int expect, int actual) {
		Assertions.assertEquals(expect,actual,string);		
	}

	@Test
	public void testLargeTxt() throws Exception {
		Message msg = new Message();
		msg.setQuestion("default._domainkey.foo.com", TXT, IN);
		msg.setServer("localhost");
		msg.setPort(8888);
		Message res = msg.queryUDP();
		int cnt = res.getAnswerCount();
		assertEquals("cnt",1, cnt);
		String expect = "v=DKIM1;t=s;p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1MjtqU+T0iWO4iqE1h1dZjRdYQ/4PWoXE5A5jz6MQDnKJ4PQFQG2+Qw9cvBVKUQZreAnAnGx8PJb+QLiBDSofRKFx10h8aCGLZ/R052dqk+8kKEbMXWFpy8s7H/JpFYJ4eYqoQWM5FRzsPe1toySFBSnVNJOrSKcWHIwI/xUOQselIFcZXaXNSmvXIxKrmZ5pgSzmdAiiofwv0M9Ls2D9SoEC0Bw3o4uxezwNEpHW8L0n4gepnuJJjtGHc6x0Okg5QE8hhLN8afKPOUz6sx88t8dQzV2nF5FKgrpx+bhB6iiyEOPD8JLWsa62Z0mL7jgDDx28KZ+eJjdlmUvXbCWxwTC5SCCCRUfhY5dhpdFZ1yybqJ9LXduKK/IgwcDxBEgTQ+SsLtcWGRWk7mAMpysLXRmUWeCbuieIY8gVY7MfQ41BbL6lK5MiIAHYDdQ0fZivknp2KStGjUF39rlLnv7nszRvJFWQaClzwZ1zGr81ez9dn2g6garKKYfIeZuIgnGpwDQtdC8TRTkhpTfJkrkefqpG278qfDxmm09G+olv7sAT5U/2/fyd5XLM2DM7Xi/71T5bZaDxFqGSsr573/93Z8zv3k8hgxONZEhUJ83PcEFJGNmec9ya3ChHU6N2ew0KjCMyo0BXVENVGmiUQkF544BUXLa3/KuI1VMBlKoOnkCAwEAAQ==";
		
		RR ansnwer = res.getAnswer().get(0);
		if (ansnwer instanceof Txt) {
			Txt txt = (Txt) ansnwer;
			Assertions.assertEquals( expect, txt.getText());
		} else {
			throw new RuntimeException("Answer is not a Txt="+ansnwer.getClass());
		}
		
		
	}
	
	@Test
	public void testAAAA() throws Exception {
		//  Random addresses (with zero groups) in the full form and in Java's
		//  form: the address bytes must match, the text must be the RFC 5952
		//  form (the old test expected a single zero group to be shown as
		//  "::", which RFC 5952 4.2.2 does not allow) and parse back the same.
		Random r = new Random();
		for(int cnt=0; cnt<9999; cnt++) {
			StringBuilder buf = new StringBuilder();
			for(int colon=0; colon<8; colon++) {
				if( colon  > 0 ) {
					buf.append(':');	
				}
				int val = r.nextInt(0x10000);
				if( val % 3 == 0) {
					val = 0;
				}
				buf.append(Integer.toHexString(val));
			}
			String ip = buf.toString();
			byte [] expect = java.net.InetAddress.getByName(ip).getAddress();

			AAAA a = new AAAA("test");
			a.setAddress(ip);
			Assertions.assertArrayEquals(expect, a.getAddress(), ip);
			String str = a.getAddressString();
			Assertions.assertTrue(str.indexOf("::") == str.lastIndexOf("::"), str);
			Assertions.assertFalse(str.matches(".*(^|:)0[0-9a-f].*"), "no leading zeros: "+str);

			AAAA b = new AAAA("test");
			b.setAddress(str);
			Assertions.assertArrayEquals(expect, b.getAddress(), ip+" -> "+str);
		}
	}


	/** RCODE 5: our non-recursive server refuses names it is not authoritative for */
	private static final int REFUSED_RCODE = 5;

	/** For a recursive server (e.g. the system resolver): a made-up name is NAME ERROR (3). */
	public void runTests(String server, int port,String ... addresses) throws Exception {
		runTests(3, server, port, addresses);
	}

	/**
	 * @param missingRcode expected RCODE for a made-up name next to the first
	 * address: 3 (NAME ERROR) from a recursive server, 5 (REFUSED) from our
	 * non-recursive test server
	 */
	public void runTests(int missingRcode, String server, int port,String ... addresses) throws Exception {
		Message msg = new Message();
		msg.setServer(server);
		msg.setPort(port);


		//msg.setTimeOut(99999999);



		//  All should be good queries
		for(String name : addresses) {
			for(int qtype : testQCodes) {				
				Message res1 = msg.query(name, qtype, IN);
				assertEquals(name+" type="+qtype+" rcode="+res1.getResponseCode(),0, res1.getResponseCode());
				// UDP is the default but here we force it just to test it
				res1 = msg.queryUDP();
				assertEquals(name+"UDP type="+qtype+" rcode="+res1.getResponseCode(),0, res1.getResponseCode());
				//  force use of TCP
				res1 = msg.queryTCP();
				assertEquals(name+"TCP type="+qtype+" rcode="+res1.getResponseCode(),0, res1.getResponseCode());

			}
		}
		// a name that does not exist / is not ours
		Message res = msg.query(addresses[0]+"x", A, IN);
		assertEquals(addresses[0]+"x type=A rcode="+res.getResponseCode(),missingRcode, res.getResponseCode());
	}

}
