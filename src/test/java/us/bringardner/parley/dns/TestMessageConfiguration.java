package us.bringardner.parley.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Properties;

import org.junit.jupiter.api.Test;

import us.bringardner.parley.core.BaseObject;
import us.bringardner.parley.core.LogLevel;
import us.bringardner.parley.core.ParleyLogger;

/** A copy of a message reads the settings of the message it was copied from, not the system properties. */
public class TestMessageConfiguration {

	@Test
	public void testACopyKeepsTheConfiguration() throws Exception {
		Properties c = new Properties();
		c.setProperty(ParleyLogger.PROPERTY_LOG_LEVEL, "WARN");
		Message m = BaseObject.makeWith(c, Message::new);
		assertEquals(LogLevel.WARN, m.getLogLevel());
		assertEquals(LogLevel.WARN, m.copy().getLogLevel());
	}
}
