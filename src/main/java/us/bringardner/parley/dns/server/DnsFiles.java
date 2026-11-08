package us.bringardner.parley.dns.server;

import java.io.IOException;
import java.util.Locale;
import java.util.Properties;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;

/**
 * Where the DNS server's files are (To-Do 18.15): its file system, from
 * {@link DnsServer#PROP_FILE_SOURCE} and its connection settings, and the file a setting names on
 * it. A setting's value is a path on that file system or a {@code filesource:} URL (a file system
 * of its own); some settings take a relative path as relative to a folder
 * ({@link DnsServer#PROP_DNS_DIR}).
 *
 * @since 2.0.0
 */
public final class DnsFiles {

	private DnsFiles() {
	}

	/**
	 * The file system the settings name: a new factory of the type {@link DnsServer#PROP_FILE_SOURCE}
	 * names, with its connection settings ({@code parley.dns.fileSource.KEY}), connected; the
	 * default factory when the setting isn't set.
	 *
	 * @param settings the settings (parley.dns.*)
	 * @return the factory
	 * @throws IOException if there is no such file system or it can't connect
	 */
	public static FileSourceFactory factory(Properties settings) throws IOException {
		return factory(settings == null ? null : settings.getProperty(DnsServer.PROP_FILE_SOURCE), settings);
	}

	/**
	 * The same, for a type read elsewhere.
	 *
	 * @param type the factory's type id ({@code sftp}, {@code jdbc}, {@code memory}...); null or
	 *        empty for the default factory
	 * @param settings where the connection settings are ({@code parley.dns.fileSource.KEY}); null for none
	 */
	public static FileSourceFactory factory(String type, Properties settings) throws IOException {
		if( type == null || type.trim().isEmpty() ) {
			return FileSourceFactory.getDefaultFactory();
		}
		String t = type.trim();
		FileSourceFactory ret = FileSourceFactory.getFileSourceFactory(t.toLowerCase(Locale.ROOT));
		if( ret == null ) {
			throw new IOException("There is no file system "+t+" ("+DnsServer.PROP_FILE_SOURCE+")");
		}
		Properties connection = connectionSettings(settings, DnsServer.PROP_FILE_SOURCE+".");
		if( !connection.isEmpty() ) {
			ret.setConnectionProperties(connection);
		}
		//  (some file systems connect when first used, others don't: connect it here)
		if( !ret.isConnected() && !ret.connect() ) {
			throw new IOException("Can't connect to the file system "+t+" ("+DnsServer.PROP_FILE_SOURCE+")");
		}
		return ret;
	}

	/**
	 * The connection settings: every setting named PREFIX + KEY ({@code parley.dns.fileSource.host}
	 * gives the connection key {@code host}), trimmed. A secret is a reference
	 * ({@code @file:...}, {@code @keychain:...}), never the secret itself.
	 */
	static Properties connectionSettings(Properties settings, String prefix) {
		Properties ret = new Properties();
		if( settings != null ) {
			for(String k : settings.stringPropertyNames()) {
				String v = settings.getProperty(k);
				if( v != null && k.startsWith(prefix) && k.length() > prefix.length() ) {
					ret.setProperty(k.substring(prefix.length()), v.trim());
				}
			}
		}
		return ret;
	}

	/**
	 * Whether a path is absolute, as File.isAbsolute() says on this system: it
	 * starts with {@code /} (and, on Windows, with {@code \} or a drive letter). Every file system
	 * takes {@code /} paths; a {@code filesource:} URL is not a path (see {@link FileSourceFactory#isUrl}).
	 */
	public static boolean isAbsolutePath(String path) {
		String p = path == null ? "" : path.trim();
		if( p.startsWith("/") ) {
			return true;
		}
		if( FileSourceFactory.isWindows() ) {
			return p.startsWith("\\") || (p.length() >= 3 && Character.isLetter(p.charAt(0)) && p.charAt(1) == ':'
					&& (p.charAt(2) == '\\' || p.charAt(2) == '/'));
		}
		return false;
	}

	/**
	 * The file a setting names, with a relative path under a folder: a {@code filesource:} URL
	 * (its own file system) or an absolute path on FACTORY ({@link FileSourceFactory#resolve}), or
	 * a relative path under DIR.
	 *
	 * @param factory the file system of a path
	 * @param dir the folder of a relative path
	 * @param value the setting's value
	 * @return the file (which may not exist)
	 * @throws IOException if the file system can't be reached
	 */
	public static FileSource resolve(FileSourceFactory factory, FileSource dir, String value) throws IOException {
		String v = value.trim();
		if( FileSourceFactory.isUrl(v) || isAbsolutePath(v) ) {
			return factory.resolve(v);
		}
		return dir.getChild(v);
	}

	/** The file next to F named its name plus SUFFIX (as the File of the path plus the suffix). */
	static FileSource sibling(FileSource f, String suffix) throws IOException {
		FileSource parent = f.getParentFile();
		return parent == null ? f.getFileSourceFactory().createFileSource(f.getPath()+suffix) : parent.getChild(f.getName()+suffix);
	}

	/**
	 * When the file was changed (ms), or 0 if it doesn't exist or can't be asked, as
	 * File.lastModified(): for stamps that only have to change when the file does.
	 */
	static long lastModified(FileSource f) {
		try {
			return f.exists() ? f.lastModified() : 0;
		} catch(IOException e) {
			return 0;
		}
	}
}
