package us.bringardner.parley.dns.server;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;

import us.bringardner.parley.dns.A;
import us.bringardner.parley.dns.AAAA;
import us.bringardner.parley.dns.Caa;
import us.bringardner.parley.dns.Cname;
import us.bringardner.parley.dns.DNS;
import us.bringardner.parley.dns.Hinfo;
import us.bringardner.parley.dns.Https;
import us.bringardner.parley.dns.Mx;
import us.bringardner.parley.dns.Ns;
import us.bringardner.parley.dns.Ptr;
import us.bringardner.parley.dns.RR;
import us.bringardner.parley.dns.Spf;
import us.bringardner.parley.dns.Srv;
import us.bringardner.parley.dns.Svcb;
import us.bringardner.parley.dns.Txt;
import us.bringardner.parley.dns.Utility;

/**
 * The record types the DNS server reads in zone files, each with its reader, an example of its
 * data and whether it can be changed (dynamic updates, the shared zone). The zone file reader,
 * the dynamic update check and the management bean's {@link DnsServerMXBean#getRecordTypes()}
 * (which management tools build their forms from) all use this table: a new type is added here,
 * with its RR class, and nowhere else.
 */
final class RecordTypes implements DNS {

	/** Reads a record's data from the fields of a zone file line: owner, TTL, type, data... (index 3 on). */
	interface Reader {
		RR read(int type, String owner, int dnsClass, List<String> f, UnaryOperator<String> fixName);
	}

	/** A type: its number, an example of its data, whether it can be changed, and its reader (null: SOA). */
	static final class Def {
		final int type;
		final String example;
		final boolean editable;
		final Reader reader;

		Def(int type, String example, boolean editable, Reader reader) {
			this.type = type;
			this.example = example;
			this.editable = editable;
			this.reader = reader;
		}

		String name() {
			return Utility.TYPENAMES[type];
		}
	}

	private static final Map<Integer, Def> TYPES = new LinkedHashMap<Integer, Def>();

	private static void add(int type, String example, boolean editable, Reader reader) {
		TYPES.put(type, new Def(type, example, editable, reader));
	}

	static {
		add(A, "192.0.2.1", true, (t, n, c, f, fix) -> {
			A a = new A(n, c);
			a.setAddress(f.get(3));
			return a;
		});
		add(AAAA, "2001:db8::1", true, (t, n, c, f, fix) -> {
			AAAA a = new AAAA(n, c);
			a.setAddress(f.get(3));
			return a;
		});
		add(CAA, "0 issue \"letsencrypt.org\"", true, (t, n, c, f, fix) -> {
			//  name TTL IN CAA flags tag "value"
			if( f.size() < 6 ) {
				throw new IllegalArgumentException("CAA needs flags tag value");
			}
			Caa caa = new Caa(n, c);
			caa.setFlags(Integer.parseInt(f.get(3)));
			caa.setTag(f.get(4));
			caa.setValue(f.get(5));
			return caa;
		});
		add(CNAME, "www.example.com.", true, (t, n, c, f, fix) -> {
			Cname r = new Cname(n, c);
			r.setCname(fix.apply(f.get(3)));
			return r;
		});
		add(DS, "12345 13 2 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", true, (t, n, c, f, fix) -> {
			//  name TTL IN DS keytag algorithm digesttype digest (the digest may be split)
			if( f.size() < 7 ) {
				throw new IllegalArgumentException("DS needs key tag, algorithm, digest type and digest");
			}
			us.bringardner.parley.dns.Ds ds = new us.bringardner.parley.dns.Ds(n, c);
			ds.setKeyTag(Integer.parseInt(f.get(3)));
			ds.setAlgorithm(Integer.parseInt(f.get(4)));
			ds.setDigestType(Integer.parseInt(f.get(5)));
			ds.setDigest(String.join("", f.subList(6, f.size())));
			return ds;
		});
		add(HINFO, "\"x86_64\" \"Linux\"", true, (t, n, c, f, fix) -> {
			Hinfo hi = new Hinfo(n, c);
			hi.setCpu(f.get(3));
			hi.setOs(f.get(4));
			return hi;
		});
		add(HTTPS, "1 . alpn=h2,h3", true, RecordTypes::svcb);
		add(MX, "10 mail.example.com.", true, (t, n, c, f, fix) -> {
			Mx mx = new Mx(n, c);
			if( f.size() > 4 ) {
				mx.setPref((short)Integer.parseInt(f.get(3)));
				mx.setExchange(fix.apply(f.get(4)));
			} else {
				//  no preference given
				mx.setExchange(fix.apply(f.get(3)));
			}
			return mx;
		});
		add(NS, "ns1.example.com.", true, (t, n, c, f, fix) -> {
			Ns r = new Ns(n, c);
			r.setNs(fix.apply(f.get(3)));
			return r;
		});
		add(PTR, "host.example.com.", true, (t, n, c, f, fix) -> {
			Ptr r = new Ptr(n, c);
			r.setPtr(fix.apply(f.get(3)));
			return r;
		});
		add(RP, "hostmaster.example.com. info.example.com.", true, (t, n, c, f, fix) -> {
			//  name TTL IN RP mbox-dname txt-dname (RFC 1183)
			if( f.size() < 5 ) {
				throw new IllegalArgumentException("RP needs mbox and txt names");
			}
			us.bringardner.parley.dns.Rp rp = new us.bringardner.parley.dns.Rp(n, c);
			rp.setMboxDname(fix.apply(f.get(3)));
			rp.setTxtDname(fix.apply(f.get(4)));
			return rp;
		});
		//  (the zone file reader reads the SOA apart: it comes first)
		add(SOA, "ns1.example.com. hostmaster.example.com. 2026010101 3600 1800 1209600 300", true, null);
		add(SPF, "\"v=spf1 mx -all\"", true, (t, n, c, f, fix) -> {
			Spf spf = new Spf(n, c);
			spf.setStrings(Zone.characterStrings(f, 3));
			return spf;
		});
		add(SRV, "10 5 443 server.example.com.", true, (t, n, c, f, fix) -> {
			//  _service._proto.name TTL IN SRV priority weight port target
			if( f.size() < 7 ) {
				throw new IllegalArgumentException("SRV needs priority weight port target");
			}
			Srv srv = new Srv(n, c);
			srv.setPriority(Integer.parseInt(f.get(3)));
			srv.setWeight(Integer.parseInt(f.get(4)));
			srv.setPort(Integer.parseInt(f.get(5)));
			String target = f.get(6);
			srv.setTarget(target.equals(".") ? "" : fix.apply(target));
			return srv;
		});
		add(SSHFP, "4 2 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", true, (t, n, c, f, fix) -> {
			//  name TTL IN SSHFP algorithm fptype fingerprint (hex, may be split)
			if( f.size() < 6 ) {
				throw new IllegalArgumentException("SSHFP needs algorithm, fingerprint type and fingerprint");
			}
			us.bringardner.parley.dns.Sshfp fp = new us.bringardner.parley.dns.Sshfp(n, c);
			fp.setAlgorithm(Integer.parseInt(f.get(3)));
			fp.setFingerprintType(Integer.parseInt(f.get(4)));
			fp.setFingerprint(String.join("", f.subList(5, f.size())));
			return fp;
		});
		add(SVCB, "1 svc.example.com. alpn=h2", true, RecordTypes::svcb);
		add(TXT, "\"v=spf1 mx -all\"", true, (t, n, c, f, fix) -> {
			Txt txt = new Txt(n, c);
			txt.setStrings(Zone.characterStrings(f, 3));
			return txt;
		});
		//  DNSSEC records: a zone signed elsewhere (dnssec-signzone, ...); never changed by hand
		for(int t : new int[] { DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM }) {
			add(t, null, false, (type, n, c, f, fix) -> PresignedRecords.parse(type, n, c, new ArrayList<String>(f.subList(3, f.size())), fix));
		}
	}

	private static RR svcb(int type, String n, int c, List<String> f, UnaryOperator<String> fix) {
		//  name TTL IN HTTPS priority target [key=value ...] (RFC 9460)
		if( f.size() < 5 ) {
			throw new IllegalArgumentException(Utility.TYPENAMES[type]+" needs priority and target");
		}
		Svcb svcb = type == HTTPS ? new Https(n, c) : new Svcb(n, c);
		svcb.setPriority(Integer.parseInt(f.get(3)));
		String target = f.get(4);
		svcb.setTarget(target.equals(".") ? "" : fix.apply(target));
		svcb.setParams(new ArrayList<String>(f.subList(5, f.size())));
		return svcb;
	}

	private RecordTypes() {
	}

	/** The type, or null if zone files can't have it. */
	static Def get(int type) {
		return TYPES.get(type);
	}

	/** Every type, in the order of the table. */
	static List<Def> all() {
		return Collections.unmodifiableList(new ArrayList<Def>(TYPES.values()));
	}
}
