/**
 * <PRE>
 *
 * Copyright Tony Bringarder 1998, 2026 <A href="http://bringardner.com/tony">Tony Bringardner</A>
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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.DnsBaseClass;
import us.bringardner.parley.dns.Message;
import us.bringardner.parley.dns.Section;
import us.bringardner.parley.dns.resolve.QueryData;
import us.bringardner.parley.net.IConnection;
import us.bringardner.parley.net.server.AbstractCommandProcessor;
import us.bringardner.parley.net.server.AbstractPrincipal;
import us.bringardner.parley.net.server.ICommand;
import us.bringardner.parley.net.server.ICommandFactory;
import us.bringardner.parley.net.server.ICommandProcessor;
import us.bringardner.parley.net.server.IPermission;
import us.bringardner.parley.net.server.IPrincipal;
import us.bringardner.parley.net.server.IRequestContext;
import us.bringardner.parley.net.server.ImmutablePrincipal;
import us.bringardner.parley.net.server.Permission;

/**
 * One admin session, on parley-net's {@link AbstractCommandProcessor} (the
 * {@link DnsAdminServer} accepts the connections).
 * <p>
 * The protocol is unchanged: lines of text; replies start with '+' (done) or
 * '-' (refused or failed), other lines are output. The session starts with a
 * greeting:
 * <ul>
 * <li>JDns.adminSecret set: {@code +JDns admin ready auth=hmac-sha256 challenge=<c>}.
 *     Nothing but {@code auth <answer>} (see {@link AdminAuth}) or {@code quit}
 *     is accepted until the client has answered the challenge.</li>
 * <li>No secret: only clients on this machine (loopback) are accepted.</li>
 * </ul>
 * After logging in, an empty line repeats the last command.
 * <p>
 * The commands belong to the session. They used to be kept in a static map
 * filled again by every new connection, so a command's output went to the
 * newest connection, even one that hadn't logged in (round 5 #73).
 */
public class DnsAdminProcessor extends AbstractCommandProcessor implements DnsAdminConstants {

	/** Default for JDns.adminMaxLine: longest admin line in bytes. */
	public static final int DEFAULT_MAX_LINE = 8*1024;
	/** Default for JDns.adminAuthTimeout: ms a client has to authenticate. */
	public static final int DEFAULT_AUTH_TIMEOUT = 30*1000;

	/** Everything an admin may do (there is one kind of admin: who knows the secret, or is local) */
	static final IPermission ADMIN = new Permission("admin");

	private final DnsServer server;
	//  This session's commands, by name
	private final Map<String, AdminCommand> commands = new TreeMap<String, AdminCommand>();
	private String secret;
	private String challenge;
	private String lastLine = STATUS;

	/** Parsed arguments: words, and -flag / -flag=value / -flag value */
	static final class CommandArgs {
		final List<String> args = new ArrayList<String>();
		final Map<String,String> flags = new TreeMap<String, String>();
	}

	/** An admin command: its output is written to this session. */
	private abstract class AdminCommand implements ICommand {
		abstract void proccess(CommandArgs args) throws IOException;

		@Override
		public IPermission getPermission() {
			return ADMIN;
		}

		@Override
		public void execute(ICommandProcessor processor, IRequestContext context) throws IOException {
			proccess(getArgs(context.getCommandLine().split(" ")));
		}
	}

	/** Who is logged in once the challenge is answered (or the client is local, without a secret) */
	private static IPrincipal adminPrincipal() {
		AbstractPrincipal p = new AbstractPrincipal("admin") {
			@Override
			public boolean authenticate(byte[] credentials) {
				return false;
			}
		};
		p.add(ADMIN);
		return new ImmutablePrincipal(p);
	}

	public DnsAdminProcessor(DnsServer server) {
		this.server = server;
		register(new AddDomain());
		register(new DeleteDomain());
		register(new Help());
		register(new ListZones());
		register(new Status());
		register(new AddDynamic());
		register(new DeleteDynamic());
		register(new DebugCommand());
		register(new Quit());
		register(new Memory());
		register(new Reset());
		register(new Resolve());
		setCommandFactory(new ICommandFactory() {
			private static final long serialVersionUID = 1L;

			@Override
			public ICommand getCommand(IRequestContext context) {
				return commands.get(context.getFirstToken());
			}
		});
	}

	private void register(AdminCommand cmd) {
		commands.put(cmd.getName(), cmd);
	}

	@Override
	public String translateResponseCode(int code) {
		//  Framework replies (a command that threw, say) in this protocol's terms
		return code < 400 ? "+" : "-";
	}

	/** The client's address, or null */
	private InetAddress peer() {
		IConnection con = getConnection();
		Socket s = con == null ? null : con.getSocket();
		return s == null ? null : s.getInetAddress();
	}

	/** JDns.adminSecret, or null if not set */
	private String adminSecret() {
		String s = server.getProperty(DnsServer.PROP_ADMIN_SECRET);
		if( s != null ) {
			s = s.trim();
			if( s.isEmpty() ) {
				s = null;
			}
		}
		return s;
	}

	/**
	 * The greeting, made here per session (it carries this session's challenge).
	 * A client that may not use the admin port is told why, and the session ends.
	 */
	@Override
	protected String takePendingGreeting() {
		super.takePendingGreeting();
		InetAddress peer = peer();
		secret = adminSecret();
		if( secret == null ) {
			if( peer == null || !peer.isLoopbackAddress() ) {
				server.log("Refused admin connection from "+peer+": "+DnsServer.PROP_ADMIN_SECRET+" is not set");
				stop();
				return "-Admin access from "+peer+" requires "+DnsServer.PROP_ADMIN_SECRET+" on the server";
			}
			setPrincipal(adminPrincipal());
			return "+JDns admin ready";
		}
		challenge = AdminAuth.newChallenge();
		return "+JDns admin ready auth=hmac-sha256 challenge="+challenge;
	}

	@Override
	protected void processLine(String line, Map<String,String> cmdUsed) throws IOException {
		if( getPrincipal() == null ) {
			login(line);
			return;
		}
		if( line.length() == 0 ) {
			line = lastLine;
		} else {
			lastLine = line;
		}
		IRequestContext context = getRequestContextFactory().getRequestContext(line);
		ICommand cmd = getCommandFactory().getCommand(context);
		if( cmd == null ) {
			reply("-UnRecognized command "+line);
			return;
		}
		try {
			cmd.execute(this, context);
		} catch(IOException ex) {
			throw ex;
		} catch(Exception ex) {
			reply("Error processing '"+line+"'");
			reply(ex.toString());
		}
	}

	/** Before the challenge is answered: only 'auth' and 'quit' */
	private void login(String line) throws IOException {
		String [] cmd = line.trim().split("[ ]+");
		if( cmd[0].equals("auth") && cmd.length == 2 && AdminAuth.verify(secret, challenge, cmd[1]) ) {
			setPrincipal(adminPrincipal());
			reply("+Authenticated");
		} else if( cmd[0].equals(QUIT) ) {
			stop();
		} else if( cmd[0].equals("auth") ) {
			server.log("Admin authentication failed from "+peer());
			//  Slow down guessing (LoginFailureDelay, 1 s by default)
			loginFailedDelay();
			reply("-Authentication failed");
			stop();
		} else {
			reply("-Authentication required");
		}
	}

	@Override
	protected void replyLineTooLong(int maxLineLength) throws IOException {
		server.log("Admin session from "+peer()+" closed: line longer than "+maxLineLength+" bytes");
		reply("-Line too long (max "+maxLineLength+" bytes)");
	}

	static CommandArgs getArgs(String args[] ) {
		CommandArgs ret = new CommandArgs();
		for(int idx=1; idx<args.length; idx++ ) {
			if( args[idx].startsWith("-")) {
				String name = args[idx].substring(1);
				String parts[] = name.split("[=]");
				if(parts.length == 1) {
					if( args.length == idx+1 ) {
						ret.flags.put(name,name);
					} else {
						if( args[idx+1].startsWith("-")) {
							ret.flags.put(name,name);
						} else {
							ret.flags.put(name,args[++idx]);
						}
					}
				} else {
					ret.flags.put(parts[0],parts[1]);
				}
			} else {
				ret.args.add(args[idx]);
			}
		}
		return ret;
	}

	// ------------------------------------------------------------------ commands

	private class DebugCommand extends AdminCommand {
		@Override
		public String getName() {
			return DEBUG;
		}

		@Override
		public String getHelp() {
			return "show or set current debug flag\n\tUsage: debug [true|false]";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			if( args.args.size() > 0) {
				DnsServer.setDebug(args.args.get(0).startsWith("t"));
			}
			reply("+Debug= "+DnsServer.isDebug());
		}
	}

	private class Help extends AdminCommand {
		@Override
		public String getName() {
			return "help";
		}

		@Override
		public String getHelp() {
			return "Get help for JDns admin commands.\n\tUsage: help [commandName,...";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			Map<String,AdminCommand> tmp = new TreeMap<String, AdminCommand>();
			if( args.args.size() == 0 ) {
				tmp = commands;
			} else {
				for(String name : args.args) {
					AdminCommand cmd = commands.get(name);
					if( cmd == null ) {
						reply("No help availible for "+name);
					} else {
						tmp.put(name, cmd);
					}
				}
			}
			for(AdminCommand cmd : tmp.values() ) {
				reply(cmd.getName()+": "+cmd.getHelp());
			}
			reply("+OK");
		}
	}

	private class ListZones extends AdminCommand {
		@Override
		public String getName() {
			return LIST;
		}

		@Override
		public String getHelp() {
			return "List all configured domains.\n\tUsage: list";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			if( args.flags.containsKey("d") ) {
				for(List<A> record: server.getDynamic().values()) {
					for(A a : record) {
						reply(a.toString());
					}
				}
			} else if( args.args.size() > 0 ) {
				Zone zone = server.getZone(args.args.get(0));
				reply(zone == null ? "No zone found for '"+args.args.get(0)+"'" : zone.toString(true));
				reply("+ListComplete");
			} else {
				for(Zone zone : server.getZones().values()) {
					reply(zone.getName());
				}
				reply("+ListComplete");
			}
		}
	}

	private class Resolve extends AdminCommand {
		final String usage = "Usage: resolve [-r] [-t=type]name [,name,...]\n\tUse -r to use the resolver instead of server query.\n\tUse -t=type to specify type (default is A)";

		@Override
		public String getName() {
			return RESOLVE;
		}

		@Override
		public String getHelp() {
			return "Resolve oen or more names. "+usage;
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			if( args.args.size()==0) {
				reply(usage);
			} else {
				String type = args.flags.get("t");
				if( type == null) {
					type = "A";
				}
				boolean isResolver = args.flags.containsKey("r");
				for(String name : args.args) {
					List<Message> result = null;
					if(isResolver) {
						Section question = new Section(name,type,Section.IN);
						Message msg = us.bringardner.parley.dns.resolve.Resolver.resolve(question);
						reply("Resolved from Resolver");
						if( msg != null ) {
							result = new ArrayList<>();
							result.add(msg);
							reply(result.toString());
						}
					} else {
						Message msg = new Message();
						msg.setQuestion(name,type,Section.IN);
						result = server.query(new QueryData(null,-1,msg));
						reply("Resolved from Server");
					}
					if( result == null ) {
						reply("Null reply ");
					} else if( result.isEmpty()) {
						reply("No reply ");
					} else {
						for(Message m : result) {
							reply(m.toString());
						}
					}
				}
			}
			reply("+Complete");
		}
	}

	private class Quit extends AdminCommand {
		@Override
		public String getName() {
			return QUIT;
		}

		@Override
		public String getHelp() {
			return "Exit the current session (Close socket)";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			reply("+Exiting");
			stop();
		}
	}

	private class Memory extends AdminCommand {
		@Override
		public String getName() {
			return MEM;
		}

		@Override
		public String getHelp() {
			return "Report the start time and free memory.";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			reply("+Start up="+server.getStartTime()+" free mem="+(Runtime.getRuntime().freeMemory()));
		}
	}

	private class Reset extends AdminCommand {
		@Override
		public String getName() {
			return RESET;
		}

		@Override
		public String getHelp() {
			return "Reset / Clear the Resoler cache ";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			reply("Cache size before ="+us.bringardner.parley.dns.resolve.Resolver.cacheSize());
			us.bringardner.parley.dns.resolve.Resolver.reset();
			reply("Cache size after ="+us.bringardner.parley.dns.resolve.Resolver.cacheSize());
			reply("+Complete");
		}
	}

	private class Status extends AdminCommand {
		@Override
		public String getName() {
			return STATUS;
		}

		@Override
		public String getHelp() {
			return "Get the current status of the DNS Server";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			reply("Server state="+server.getState());
			reply(us.bringardner.parley.dns.resolve.Resolver.getStats());
			String type = args.args.size() > 0 ? args.args.get(0) : ALL;
			if( type.equals(RESOLVER) || type.equals(ALL)) {
				sendStatus(RESOLVER,us.bringardner.parley.dns.resolve.Resolver.getResolvers());
			}
			if( type.equals(TCP) || type.equals(ALL)) {
				sendStatus(TCP,server.getTCPProsessors());
			}
			if( type.equals(UDP) || type.equals(ALL)) {
				sendStatus(UDP,server.getUDPProsessors());
			}
			reply("+Status done");
		}
	}

	private void sendStatus(String type, DnsBaseClass [] procs) throws IOException {
		reply("");
		reply("State of "+procs.length+" "+type+ " processors follows");
		for(int i=0; i< procs.length; i++ ) {
			reply("\t"+i+" "+procs[i].getState());
		}
	}

	private class AddDynamic extends AdminCommand {
		final String usage = "-Usage: "+ADD_DYNAMIC+" name [ipAddress]\n\tIf ipAddress is not provided the client address will be used.";

		@Override
		public String getName() {
			return ADD_DYNAMIC;
		}

		@Override
		public String getHelp() {
			return "Add or update a dynamic address.\n\t"+usage;
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			if( args.args.size() == 0) {
				reply(usage);
				return;
			}
			String name = args.args.get(0);
			String addr;
			if( args.args.size() == 1) {
				//  The address of this session's client
				InetAddress peer = peer();
				if( peer == null ) {
					reply("-No client address: give one");
					return;
				}
				addr = peer.isLoopbackAddress() ? InetAddress.getLocalHost().getHostAddress() : peer.getHostAddress();
			} else {
				addr = args.args.get(1);
			}
			try {
				server.addOrUpdateDynamic(name, addr);
			} catch (ClassNotFoundException | SQLException e1) {
				throw new IOException(e1);
			}
			reply("+"+name+"  set to addr="+addr);
		}
	}

	private class DeleteDynamic extends AdminCommand {
		@Override
		public String getName() {
			return DEL_DYNAMIC;
		}

		@Override
		public String getHelp() {
			return "Delete a dynamic address.\n\tUsage: del_dynamic name [,name,..]";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			if( args.args.size() < 1) {
				reply("-Usage: del_dynamic name [,name,..]");
			} else {
				for(String name : args.args) {
					server.removeDynamic(name);
				}
				reply("+OK");
			}
		}
	}

	private class AddDomain extends AdminCommand {
		@Override
		public String getName() {
			return ADD_DOMAIN;
		}

		@Override
		public String getHelp() {
			return ADD_DOMAIN+" Add a domain to the server.\n\tUsage: "+ADD_DOMAIN+" name [,name,..]";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			if( args.args.size() < 1) {
				reply("-Usage: "+ADD_DOMAIN+" name [,name,..]");
			} else {
				for(String name : args.args) {
					server.addDomain(name);
				}
				reply("+OK");
			}
		}
	}

	private class DeleteDomain extends AdminCommand {
		@Override
		public String getName() {
			return DEL_DOMAIN;
		}

		@Override
		public String getHelp() {
			return DEL_DOMAIN+" Delete a domain to the server.\n\tUsage: "+DEL_DOMAIN+" name [,name,..]";
		}

		@Override
		void proccess(CommandArgs args) throws IOException {
			if( args.args.size() < 1) {
				reply("-Usage: "+DEL_DOMAIN+" name [,name,..]");
			} else {
				for(String name : args.args) {
					server.removeDomain(name);
				}
				reply("+OK");
			}
		}
	}
}
