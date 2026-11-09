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
package us.bringardner.parley.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.util.RenamedProperty;
import us.bringardner.parley.files.FileSource;

/**
 * Property naming rules: every property has a PROP_ constant whose value
 * starts with "parley.dns.", and every one is listed in README.md. (NsLookup, a
 * separate tool, is not covered.)
 */
public class TestPropertyNames {

	private static final String [] CLASSES = {
			"us.bringardner.parley.dns.server.DnsServer",
			"us.bringardner.parley.dns.server.UDPProsessor",
			"us.bringardner.parley.dns.resolve.Resolver",
			"us.bringardner.parley.dns.resolve.ResolverThread"
	};

	/** The values of every PROP_ constant. */
	private static List<String> propertyNames() throws Exception {
		List<String> ret = new ArrayList<String>();
		for(String c : CLASSES) {
			for(Field f : Class.forName(c).getDeclaredFields()) {
				if( f.getName().startsWith("PROP_") && Modifier.isStatic(f.getModifiers()) && f.getType() == String.class ) {
					f.setAccessible(true);
					ret.add(c.substring(c.lastIndexOf('.')+1)+"."+f.getName()+"="+f.get(null));
				}
			}
		}
		return ret;
	}

	@Test
	public void constantsStartWithJDns() throws Exception {
		List<String> names = propertyNames();
		assertTrue(names.size() > 50, names.toString());
		for(String n : names) {
			assertTrue(n.substring(n.indexOf('=')+1).startsWith("parley.dns."), n);
		}
	}

	@Test
	public void everyPropertyIsInTheReadme() throws Exception {
		String readme = new String(TestFiles.bytes(Fixtures.projectDir().getChild("README.md")), StandardCharsets.UTF_8);
		for(String n : propertyNames()) {
			String value = n.substring(n.indexOf('=')+1);
			assertTrue(readme.contains("`"+value+"`"), value+" ("+n.substring(0, n.indexOf('='))+") is not in README.md");
		}
	}

	@Test
	public void noPropertyReadWithoutAConstant() throws Exception {
		//  Literal names passed to the property readers (NsLookup excluded)
		Pattern p = Pattern.compile("(?:getProperty|stringProperty|intProperty|RenamedProperty\\.get)\\(\\s*\"([^\"]+)\"");
		List<String> found = new ArrayList<String>();
		for(FileSource f : sources(Fixtures.projectDir().getChild("src/main/java"))) {
			if( f.getName().equals("NsLookup.java") ) {
				continue;
			}
			String text = new String(TestFiles.bytes(f), StandardCharsets.UTF_8);
			Matcher m = p.matcher(text);
			while( m.find() ) {
				found.add(f.getName()+": "+m.group(1));
			}
		}
		assertEquals("[]", found.toString());
	}

	private static List<FileSource> sources(FileSource dir) throws IOException {
		List<FileSource> ret = new ArrayList<FileSource>();
		FileSource [] list = dir.listFiles();
		if( list != null ) {
			for(FileSource f : list) {
				if( f.isDirectory() ) {
					ret.addAll(sources(f));
				} else if( f.getName().endsWith(".java") ) {
					ret.add(f);
				}
			}
		}
		return ret;
	}

	@Test
	public void oldNamesStillWork() {
		String name = "parley.dns.testRenamed";
		String old = "TestRenamedOld";
		try {
			assertNull(RenamedProperty.get(name, old));
			System.setProperty(old, "7");
			assertEquals("7", RenamedProperty.get(name, old), "the old name is read");
			System.setProperty(name, "8");
			assertEquals("8", RenamedProperty.get(name, old), "the new name wins");
			System.clearProperty(name);
			System.clearProperty(old);
			assertEquals("d", RenamedProperty.get(name, old, "d"));
		} finally {
			System.clearProperty(name);
			System.clearProperty(old);
		}
	}
}
