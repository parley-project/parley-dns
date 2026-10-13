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
 */
package us.bringardner.parley.dns.util;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import us.bringardner.parley.dns.Sshfp;

/**
 * Prints SSHFP records (RFC 4255) for SSH host keys, to put in a signed zone:
 * <pre>
 *   java us.bringardner.parley.dns.util.SshfpTool [-sha1] host [key.pub ...]
 * </pre>
 * Without key files it reads /etc/ssh/ssh_host_*_key.pub. Records are SHA-256
 * fingerprints; -sha1 adds SHA-1 ones for old clients. Like ssh-keygen -r.
 */
public final class SshfpTool {

	private SshfpTool() {
	}

	public static void main(String [] args) throws IOException {
		System.exit(run(args, System.out, System.err));
	}

	/** @return the exit code */
	static int run(String [] args, PrintStream out, PrintStream err) throws IOException {
		boolean sha1 = false;
		List<String> rest = new ArrayList<String>();
		for(String a : args) {
			if( a.equals("-sha1") ) {
				sha1 = true;
			} else {
				rest.add(a);
			}
		}
		if( rest.isEmpty() ) {
			err.println("Usage: SshfpTool [-sha1] host [key.pub ...]");
			return 2;
		}
		String host = rest.get(0);
		List<File> files = new ArrayList<File>();
		for(String f : rest.subList(1, rest.size())) {
			files.add(new File(f));
		}
		if( files.isEmpty() ) {
			File[] found = new File("/etc/ssh").listFiles((d, n) -> n.startsWith("ssh_host_") && n.endsWith("_key.pub"));
			if( found != null ) {
				Arrays.sort(found);
				files.addAll(Arrays.asList(found));
			}
		}
		if( files.isEmpty() ) {
			err.println("No host key files found");
			return 1;
		}
		String owner = host.endsWith(".") ? host : host+".";
		int errors = 0;
		for(File f : files) {
			for(String line : Files.readAllLines(f.toPath(), StandardCharsets.US_ASCII)) {
				if( line.trim().isEmpty() || line.trim().startsWith("#") ) {
					continue;
				}
				try {
					byte [] blob = Sshfp.keyBlob(line);
					List<Integer> types = sha1 ? Arrays.asList(Sshfp.SHA1, Sshfp.SHA256) : Arrays.asList(Sshfp.SHA256);
					for(int t : types) {
						Sshfp fp = Sshfp.forKey(owner, blob, t);
						out.println(owner+" IN SSHFP "+fp.getRdataAsString());
					}
				} catch(IllegalArgumentException ex) {
					err.println(f+": "+ex.getMessage());
					errors++;
				}
			}
		}
		return errors == 0 ? 0 : 1;
	}
}
