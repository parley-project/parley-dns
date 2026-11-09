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
 */
package us.bringardner.parley.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.dns.resolve.RemoteServer;
import us.bringardner.parley.dns.resolve.ServerA;

/**
 * Offline tests for state shared between threads: RemoteServer rotation.
 */
public class TestThreadSafeState {

	@Test
	public void remoteServerRotationIsThreadSafe() throws Exception {
		RemoteServer rs = new RemoteServer("example.test");
		rs.addAddress("a","10.0.4.1");
		rs.addAddress("b","10.0.4.2");
		rs.addAddress("c","10.0.4.3");
		AtomicReference<String> failure = new AtomicReference<String>();
		Set<String> firsts = java.util.Collections.synchronizedSet(new HashSet<String>());
		List<Thread> list = new ArrayList<Thread>();
		for(int t=0; t< 8; t++ ) {
			Thread th = new Thread(() -> {
				try {
					for(int i=0; i< 20000; i++ ) {
						Iterator<ServerA> it = rs.iterator();
						int n = 0;
						while( it.hasNext() ) {
							ServerA s = it.next();
							if( n++ == 0 ) {
								firsts.add(s.toString());
							}
						}
						if( n != 3 ) {
							failure.compareAndSet(null,"iterated "+n+" servers");
						}
					}
				} catch(Throwable ex) {
					failure.compareAndSet(null, ex.toString());
				}
			});
			list.add(th);
			th.start();
		}
		for(Thread th : list) {
			th.join(30_000);
		}
		assertNull(failure.get(), failure.get());
		assertEquals(3, firsts.size(), "starting server rotates over all addresses");
	}
}
