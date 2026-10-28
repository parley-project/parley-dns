package us.bringardner.parley.dns.server;

import us.bringardner.parley.dns.Message;
import us.bringardner.parley.net.server.ServerContext;
import us.bringardner.parley.net.server.ServerMain;
import us.bringardner.parley.net.server.ServerProvider;

/**
 * The DNS server for parley-net's launcher, as {@code dns} in {@code parley.servers}: the launcher
 * reads {@code parley-dns.properties} (or the file {@code parley.dns.configFile} names), starts and
 * stops it, and shows it over JMX as {@code us.bringardner.parley:type=Server,name=dns} like every
 * Parley server; while it runs, {@code us.bringardner.parley:type=Dns,name=dns} ({@link DnsServerMXBean})
 * adds its zones and records.
 * <p>
 * It reads its settings from the system properties (the launcher sets them from its files for such
 * providers), so one DNS server runs per JVM.
 *
 * @since 2.0.0
 */
public class DnsServerProvider implements ServerProvider {

	@Override
	public String id() {
		return "dns";
	}

	@Override
	public String description() {
		return "DNS (port "+Integer.getInteger(DnsServer.PROP_PORT, Message.DNSPORT)+")";
	}

	@Override
	public String configProperty() {
		return DnsServer.PROP_DNS_PROPERTIES;
	}

	@Override
	public ServerMain.Service create(ServerContext context) throws Exception {
		DnsServer svr = new DnsServer();
		return DnsServer.service(svr, "DNS server", bean -> context.register("Dns", id(), bean), context::unregister);
	}
}
