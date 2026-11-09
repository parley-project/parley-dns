package us.bringardner.parley.dns;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import us.bringardner.parley.files.FileSource;
import us.bringardner.parley.files.FileSourceFactory;
import us.bringardner.parley.files.memory.MemoryFileSourceFactory;

/**
 * FileSources for tests (To-Do 18.15, as parley-net's TestFiles): a JUnit {@code @TempDir} on the
 * local file system, or a folder of a new memory file system, so a test can run on both.
 * ({@code @TempDir} gives a java.nio.file.Path: it is only turned into a FileSource here.)
 */
public final class TestFiles {

	/** The local file system (a FileProxy for the @TempDir) */
	public static final String LOCAL = "local";
	/** A new memory file system */
	public static final String MEMORY = "memory";

	private TestFiles() {
	}

	/** The @TempDir as a FileSource on the local file system */
	public static FileSource local(Path tempDir) throws IOException {
		return FileSourceFactory.fileProxyFactory.createFileSource(tempDir.toAbsolutePath().toString());
	}

	/** A new, empty folder: the @TempDir (LOCAL), or a folder of a new memory file system (MEMORY) */
	public static FileSource folder(String type, Path tempDir) throws IOException {
		if( LOCAL.equals(type) ) {
			return local(tempDir);
		}
		FileSourceFactory memory = new MemoryFileSourceFactory();
		memory.connect();
		FileSource ret = memory.createFileSource("/test"+System.nanoTime());
		if( !ret.mkdirs() ) {
			throw new IOException("Can't make "+ret);
		}
		return ret;
	}

	/** A new, empty folder with a unique name (PREFIX and a number) in the @TempDir */
	public static FileSource newFolder(Path tempDir, String prefix) throws IOException {
		return newFolder(local(tempDir), prefix);
	}

	/** A new, empty folder with a unique name (PREFIX and a number) in DIR */
	public static FileSource newFolder(FileSource dir, String prefix) throws IOException {
		return dir.getFileSourceFactory().createTempDirectory(prefix, dir);
	}

	/** A new folder under DIR (made) */
	public static FileSource mkdir(FileSource dir, String name) throws IOException {
		FileSource ret = dir.getChild(name);
		if( !ret.mkdirs() && !ret.isDirectory() ) {
			throw new IOException("Can't make "+ret);
		}
		return ret;
	}

	/**
	 * What a setting holds to name F: its path for a local file, else its {@code filesource:} URL
	 * (with the memory file system's session, so it is the same one)
	 */
	public static String setting(FileSource f) throws IOException {
		return f.getFileSourceFactory() == FileSourceFactory.fileProxyFactory ? f.getPath() : f.toURL().toString();
	}

	/** Write TEXT (UTF-8) to F */
	public static FileSource write(FileSource f, String text) throws IOException {
		try(OutputStream out = f.getOutputStream()) {
			out.write(text.getBytes(StandardCharsets.UTF_8));
		}
		return f;
	}

	/** Write DATA to F */
	public static FileSource writeBytes(FileSource f, byte[] data) throws IOException {
		try(OutputStream out = f.getOutputStream()) {
			out.write(data);
		}
		return f;
	}

	/** Append DATA to F */
	public static FileSource appendBytes(FileSource f, byte[] data) throws IOException {
		try(OutputStream out = f.getOutputStream(true)) {
			out.write(data);
		}
		return f;
	}

	/** A writer of F's text (UTF-8), from the start */

	public static Writer writer(FileSource f) throws IOException {
		return new OutputStreamWriter(f.getOutputStream(), StandardCharsets.UTF_8);
	}

	/** F's lines (UTF-8) */
	public static List<String> lines(FileSource f) throws IOException {
		List<String> ret = new ArrayList<String>();
		try(BufferedReader in = new BufferedReader(new InputStreamReader(f.getInputStream(), StandardCharsets.UTF_8))) {
			String line;
			while( (line = in.readLine()) != null ) {
				ret.add(line);
			}
		}
		return ret;
	}

	/** Append TEXT (UTF-8) to F */
	public static FileSource append(FileSource f, String text) throws IOException {
		try(OutputStream out = f.getOutputStream(true)) {
			out.write(text.getBytes(StandardCharsets.UTF_8));
		}
		return f;
	}

	/** F's bytes */
	public static byte[] bytes(FileSource f) throws IOException {
		try(InputStream in = f.getInputStream()) {
			return in.readAllBytes();
		}
	}

	/** F's text (UTF-8) */
	public static String read(FileSource f) throws IOException {
		return new String(bytes(f), StandardCharsets.UTF_8);
	}

	/** Copy FROM's bytes to TO */
	public static FileSource copy(FileSource from, FileSource to) throws IOException {
		byte[] data = bytes(from);
		try(OutputStream out = to.getOutputStream()) {
			out.write(data);
		}
		return to;
	}


}
