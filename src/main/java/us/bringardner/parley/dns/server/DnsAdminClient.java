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
 * ~version~V000.01.02-V000.00.05-V000.00.00-
 */
package us.bringardner.parley.dns.server;

import java.io.IOException;
import java.util.Scanner;

import javax.net.SocketFactory;

import us.bringardner.parley.dns.util.NsLookup;
import us.bringardner.parley.net.client.Client;

/**
 * 
 * Creation date: (6/16/2003 10:53:15 AM)
 * @author: Tony Bringardner
 */
public class DnsAdminClient implements DnsAdminConstants {
	private static SocketFactory socketFactory = SocketFactory.getDefault();
	//  parley-net's client: connect timeout, line length limit, TLS
	private Client client;
	private String adminHost;
	private int adminPort;
	private int timeout = 2000;
	//  Shared secret for servers that require authentication (default: parley.dns.adminSecret property)
	private String secret = System.getProperty(DnsServer.PROP_ADMIN_SECRET);

	/**
	 * AdminClient constructor comment.
	 */
	public DnsAdminClient() {
		super();
	}

	public static void main(String args[]) throws IOException  {

		String name = System.getProperty(DnsServer.PROP_ADMIN_HOST);
		if( args.length>0) {
			name = args[0];
		}
		if( name == null ) {
			name = NsLookup.getDnsServer();
			if( name == null ) {
				name = "localhost";
			}
		}

		int port = DnsServer.getAdminPort();
		String tmp = System.getProperty(DnsServer.PROP_ADMIN_PORT);
		if( tmp == null && args.length>1) {
			tmp = args[1];
		}
		if( tmp != null ) {
			try {
				port = Integer.parseInt(tmp);
			} catch (Exception e) {
			}
		}

		DnsAdminClient client = new DnsAdminClient(name,port);
		if( client.connect()) {
			try (Scanner in = new Scanner(System.in)) {
				System.out.print("DNS Admin>");
				while(in.hasNext()) {
					String cmd = in.nextLine();
					if( cmd == null ) {
						client.close();
						return;
					}
					if( cmd.isEmpty()) {
						try {
							String res = client.sendCommand(cmd);
							System.out.println(res);
							if( QUIT.equals(cmd)) {
								return;
							}
						} catch (Exception e) {
							e.printStackTrace();
							return;
						}
						System.out.print("DNS Admin>");
					}
				}
			}
		} else {
			System.out.println("Could not connecct to "+name+":"+port);
		}


	}

	/**
	 * AdminClient constructor comment.
	 */
	public DnsAdminClient(String host, int port) throws IOException{
		this.adminHost = host;
		this.adminPort = port;
	}


	public String getAdminHost() {
		return adminHost;
	}

	public void setAdminHost(String adminHost) {
		this.adminHost = adminHost;
	}

	public int getAdminPort() {
		return adminPort;
	}

	public void setAdminPort(int adminPort) {
		this.adminPort = adminPort;
	}

	/** Shared secret used to answer the server's challenge (parley.dns.adminSecret on the server). */
	public void setSecret(String secret) {
		this.secret = secret;
	}

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	public boolean connect()  {
		boolean ret = false;
		try {
			javax.net.SocketFactory factory = getSocketFactory();
			if( factory == SocketFactory.getDefault()
					&& Boolean.parseBoolean(System.getProperty(DnsServer.PROP_ADMIN_TLS, "false").trim()) ) {
				factory = javax.net.ssl.SSLSocketFactory.getDefault();
			}
			//  no host: this machine, as java.net.Socket takes it
			String host = adminHost == null ? java.net.InetAddress.getLoopbackAddress().getHostAddress() : adminHost;
			Client c = new Client(host, adminPort, true);
			c.setSocketFactory(factory);
			//  as before: the admin certificate is checked against the trust store, not the host name
			c.setVerifyHostname(false);
			c.setConnectTimeout(Math.max(getTimeout(), 2000));
			if( !c.connect() ) {
				System.out.println(c.getLastConnectError());
				return false;
			}
			client = c;
			c.setTimeout(getTimeout());
			String tmp = c.readLine();
			if( tmp != null && tmp.startsWith("+")) {
				String challenge = AdminAuth.challengeFrom(tmp);
				if( challenge == null ) {
					ret = true;
				} else if( secret == null || secret.trim().isEmpty() ) {
					System.out.println("Server requires authentication: set the secret ("+DnsServer.PROP_ADMIN_SECRET+")");
				} else {
					c.writeLine("auth "+AdminAuth.response(secret.trim(), challenge));
					c.flush();
					tmp = c.readLine();
					if( tmp != null && tmp.startsWith("+") ) {
						ret = true;
					} else {
						System.out.println("Authentication failed: "+tmp);
					}
				}
			} else {
				System.out.println("Connected but invalid prompt from server="+tmp);
			}
		} catch (Exception e) {
			System.out.println(e);
		}
		if( !ret ) {
			closeQuietly();
		}
		return  ret;
	}

	public void close() {
		if( client != null ) {
			try {
				sendCommand(QUIT);
			} catch(Exception ex){}
		}
		closeQuietly();
	}

	private void closeQuietly() {
		Client c = client;
		client = null;
		if( c != null ) {
			try {
				c.close();
			} catch(IOException ex) {
				// gone already
			}
		}
	}

	private String executePreDefined(String cmd,String ... args ) throws IOException {
		if( args == null || args.length == 0 ) {
			return("Usage:"+cmd+" name [name...]");			
		}

		// concat all args
		
		StringBuilder buf = new StringBuilder(cmd);
		for(String d : args) {
			buf.append(" "+d);
		}
		String ret = sendCommand(buf.toString());
		
	
		return ret;
	}

	public String memory() throws IOException {
		return sendCommand(MEM);
	}

	public String list() throws IOException {
		return sendCommand(LIST);
	}

	public String reset() throws IOException {
		return sendCommand(RESET);
	}

	public String statusALL() throws IOException {
		return sendCommand(STATUS+" "+ALL);
	}

	public String statusUDP() throws IOException {
		return sendCommand(STATUS+" "+UDP);
	}

	public String statusTCP() throws IOException {
		return sendCommand(STATUS+" "+TCP);
	}

	public String statusResolver() throws IOException {
		return sendCommand(STATUS+" "+RESOLVER);
	}

	public String debug(String ... args) throws IOException {
		return executePreDefined(DEBUG, args);
	}


	public void addDynamic(String ... args ) throws IOException {
		executePreDefined(ADD_DYNAMIC, args);
	}

	public void removeDynamic(String ... args ) throws IOException {
		executePreDefined(DEL_DYNAMIC, args);
	}



	/**
	 * 
	 * Creation date: (6/16/2003 10:58:49 AM)
	 * @return javax.net.SocketFactory
	 */
	public static javax.net.SocketFactory getSocketFactory() {
		return socketFactory;
	}


	private String sendCommand(String cmd) throws IOException {

		Client c = client;
		if( c == null ) {
			throw new IOException("Not connected");
		}
		StringBuilder ret = new StringBuilder();
		c.writeLine(cmd);
		c.flush();

		String tmp = null;
		boolean done = false;

		while ( !done && (tmp=c.readLine())!=null) {
			ret.append(tmp+"\n");
			if( tmp.startsWith("+") || tmp.startsWith("-") ) {
				done = true;
			} 
		}
		
		return ret.toString();


	}

	/**
	 * 
	 * Creation date: (6/16/2003 10:58:49 AM)
	 * @param newSocketFactory javax.net.SocketFactory
	 */
	public static void setSocketFactory(javax.net.SocketFactory newSocketFactory) {
		socketFactory = newSocketFactory;
	}


}
