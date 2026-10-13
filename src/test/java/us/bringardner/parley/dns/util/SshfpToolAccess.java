package us.bringardner.parley.dns.util;

import java.io.PrintStream;

/** Lets tests in other packages run SshfpTool without System.exit. */
public final class SshfpToolAccess {
	private SshfpToolAccess() {
	}

	public static int run(String [] args, PrintStream out, PrintStream err) {
		return SshfpTool.run(args, out, err);
	}
}
