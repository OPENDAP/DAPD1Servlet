/**
 * 
 */
package org.opendap.d1;

import java.io.File;
import java.sql.SQLException;

import junit.framework.TestCase;

import org.dataone.service.types.v1.Log;
import org.dataone.service.types.v1.LogEntry;
import org.opendap.d1.DatasetsDatabase.DAPDatabaseException;

/**
 * @author jimg
 *
 */
public class LogDatabaseTest extends TestCase {
	
	// LogDatabase logDB = null;

	/**
	 * @param name
	 */
	public LogDatabaseTest(String name) {
		super(name);
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#setUp()
	 */
	protected void setUp() throws Exception {
		super.setUp();
	}

	/* (non-Javadoc)
	 * @see junit.framework.TestCase#tearDown()
	 */
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	/**
	 * Test method for {@link org.opendap.d1.LogDatabase#LogDatabase()}.
	 */
	public final void testLogDatabase() {
		LogDatabase db = null;
		try {
			db = new LogDatabase("empty.db", "testNodeId");
			assertTrue("The log database empty.db shouldbe valid after creation", db.isValid());
		} catch (Exception e) {
			e.printStackTrace();
			fail("Could not open and initialize an empty DB");
		} 
		
		// this removes the newly made log DB so that we can test making it from scratch 
		// each time this code is run.
		try {
			db.finalize();	
			File file = new File("empty.db");
			file.delete();
		} catch (Throwable e) {
			e.printStackTrace();
			fail("Could not run finalize() on newly created DB");
		}
		
		
		// existing.db is in version control; it is an empty log database
		try {
			db = new LogDatabase("existing.db", "testNodeId");
			assertTrue("The log database existing.db shouldbe valid", db.isValid());
		} catch (Exception e) {
			e.printStackTrace();
			fail("Could not open an empty DB");
		} 

		// finalize() gets called when the object goes out of scope.
	}
	
	/**
	 * Test method for {@link org.opendap.d1.LogDatabase#addEntry(java.lang.String, java.lang.String, java.lang.String, java.lang.String)}.
	 */
	public final void testAddEntry() {
		LogDatabase db = null;
		try {
			db = new LogDatabase("forTestAddEntry.db", "testNodeId");
			assertTrue("The log database empty.db shouldbe valid after creation", db.isValid());
		} catch (Exception e) {
			e.printStackTrace();
			fail("Could not open and initialize an empty DB");
		} 
		
		try {
			assertEquals("There should be zero rows in the Log before addEntry is called", 0, db.count());
		} catch (SQLException e1) {
			e1.printStackTrace();
			fail("count() threw an excpetion");
		}
		
		try {
			db.addEntry("PID1", "128.0.0.1", "unit tests", "test");
			db.addEntry("PID1", "128.0.0.1", "unit tests", "set");
			db.addEntry("PID2", "128.0.0.1", "unit tests", "test");
			db.addEntry("PID3", "128.0.0.1", "unit tests", "test");
		} catch (SQLException e1) {
			e1.printStackTrace();
			fail("addEntry threw an exception");
		}
		
		try {
			assertEquals("There should be 4 rows in the Log before addEntry is called", 4, db.count());
		} catch (SQLException e1) {
			e1.printStackTrace();
			fail("count() threw an excpetion");
		}
		
		try {
			db.finalize();	
		} catch (Throwable e) {
			e.printStackTrace();
			fail("Could not run finalize() on newly created DB");
		}
		
		File file = new File("forTestAddEntry.db");
		file.delete();
	}

	/**
	 * Test method for {@link org.opendap.d1.LogDatabase#dump()}.
	 */
	public final void testDump() {
		LogDatabase db = null;
		try {
			db = new LogDatabase("LogTest.db", "testNodeId");
			
			assertTrue("The log database empty.db shouldbe valid after creation", db.isValid());
			assertEquals("There should be 4 rows in the Log before addEntry is called", 4, db.count());
			
			db.dump();
		} catch (Exception e1) {
			e1.printStackTrace();
			fail("dump() threw an exception");
		}
	}

	/**
	 * Test method for {@link org.opendap.d1.LogDatabase#getMatchingLogEntries(java.lang.String, int, int)}.
	 */
	public final void testGetMatchingLogEntries1() {
		LogDatabase db = null;
		try {
			db = new LogDatabase("LogTest.db", "testNodeId");
			
			assertTrue("The log database empty.db shouldbe valid after creation", db.isValid());
			assertEquals("There should be 4 rows in the Log before addEntry is called", 4, db.count());
		} catch (Exception e1) {
			e1.printStackTrace();
			fail("failed to open the test database");
		}

		try {
			Log logLines = db.getMatchingLogEntries("", 0, 4);
			assertEquals("There should be 4 log lines", 4, logLines.sizeLogEntryList());
			
			LogEntry entry = logLines.getLogEntry(0);
			assertEquals("The first entryId should be 1", "1", entry.getEntryId());
			assertEquals("The first identifier should be PID1", "PID1", entry.getIdentifier().getValue());
			
			entry = logLines.getLogEntry(1);
			assertEquals("The second entryId should be 2", "2", entry.getEntryId());
			assertEquals("The second identifier should be PID1", "PID1", entry.getIdentifier().getValue());
			
			// skip #3
			
			entry = logLines.getLogEntry(3);
			assertEquals("The fourth entryId should be 4", "4", entry.getEntryId());
			assertEquals("The fourth identifier should be PID3", "PID3", entry.getIdentifier().getValue());
			
		} catch (SQLException e) {
			e.printStackTrace();
			fail("getMatchingLogEntries threw SQLException: " + e.getMessage());
		} catch (DAPDatabaseException e) {
			e.printStackTrace();
			fail("getMatchingLogEntries threw DAPDatabaseException" + e.getMessage());
		}
	}

	/**
	 * Test method for {@link org.opendap.d1.LogDatabase#getMatchingLogEntries(java.lang.String, int, int)}.
	 */
	public final void testGetMatchingLogEntries2() {
		LogDatabase db = null;
		try {
			db = new LogDatabase("LogTest.db", "testNodeId");
			
			assertTrue("The log database empty.db shouldbe valid after creation", db.isValid());
			assertEquals("There should be 4 rows in the Log before addEntry is called", 4, db.count());
		} catch (Exception e1) {
			e1.printStackTrace();
			fail("failed to open the test database");
		}

		try {
			Log logLines = db.getMatchingLogEntries("", 2, 4);
			assertEquals("There should be 2 log lines", 2, logLines.sizeLogEntryList());
			
			LogEntry entry = logLines.getLogEntry(0);
			assertEquals("The first entryId should be 3", "3", entry.getEntryId());
			assertEquals("The first identifier should be PID2", "PID2", entry.getIdentifier().getValue());
			
			entry = logLines.getLogEntry(1);
			assertEquals("The second entryId should be 4", "4", entry.getEntryId());
			assertEquals("The second identifier should be PID3", "PID3", entry.getIdentifier().getValue());
			
		} catch (SQLException e) {
			e.printStackTrace();
			fail("getMatchingLogEntries threw SQLException: " + e.getMessage());
		} catch (DAPDatabaseException e) {
			e.printStackTrace();
			fail("getMatchingLogEntries threw DAPDatabaseException" + e.getMessage());
		}
	}

	/**
	 * Test method for {@link org.opendap.d1.LogDatabase#getMatchingLogEntries(java.lang.String, int, int)}.
	 */
	public final void testGetMatchingLogEntries3() {
		LogDatabase db = null;
		try {
			db = new LogDatabase("LogTest.db", "testNodeId");
			
			assertTrue("The log database empty.db shouldbe valid after creation", db.isValid());
			assertEquals("There should be 4 rows in the Log before addEntry is called", 4, db.count());
		} catch (Exception e1) {
			e1.printStackTrace();
			fail("failed to open the test database");
		}

		try {
			Log logLines = db.getMatchingLogEntries("", 0, 2);
			assertEquals("There should be 2 log lines", 2, logLines.sizeLogEntryList());
			
			LogEntry entry = logLines.getLogEntry(0);
			assertEquals("The first entryId should be 1", "1", entry.getEntryId());
			assertEquals("The first identifier should be PID1", "PID1", entry.getIdentifier().getValue());
			
			entry = logLines.getLogEntry(1);
			assertEquals("The second entryId should be 2", "2", entry.getEntryId());
			assertEquals("The second identifier should be PID1", "PID1", entry.getIdentifier().getValue());
						
		} catch (SQLException e) {
			e.printStackTrace();
			fail("getMatchingLogEntries threw SQLException: " + e.getMessage());
		} catch (DAPDatabaseException e) {
			e.printStackTrace();
			fail("getMatchingLogEntries threw DAPDatabaseException" + e.getMessage());
		}
	}

	/**
	 * Test if  "WHERE 'string%' LIKE identifier" works.
	 * 
	 * Test method for {@link org.opendap.d1.LogDatabase#getMatchingLogEntries(java.lang.String, int, int)}.
	 */
	public final void testGetMatchingLogEntries4() {
		LogDatabase db = null;
		try {
			db = new LogDatabase("LogTest.db", "testNodeId");
			
			assertTrue("The log database empty.db shouldbe valid after creation", db.isValid());
			assertEquals("There should be 4 rows in the Log before addEntry is called", 4, db.count());
		} catch (Exception e1) {
			e1.printStackTrace();
			fail("failed to open the test database");
		}

		try {
			Log logLines = db.getMatchingLogEntries("where PID like 'P%'", 0, 10);
			assertEquals("There should be 4 log lines", 4, logLines.sizeLogEntryList());
		} catch (SQLException e) {
			e.printStackTrace();
			fail("getMatchingLogEntries threw SQLException: " + e.getMessage());
		} catch (DAPDatabaseException e) {
			e.printStackTrace();
			fail("getMatchingLogEntries threw DAPDatabaseException" + e.getMessage());
		}
	}

}
