/**
 *  Copyright: 2014 OpenDAP, Inc.
 *
 * Author: James Gallagher <jgallagher@opendap.org>
 * 
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * You can contact OpenDAP, Inc. at PO Box 112, Saunderstown, RI. 02874-0112.
 */
package org.opendap.d1;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.dataone.service.types.v1.Event;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.Log;
import org.dataone.service.types.v1.LogEntry;
import org.dataone.service.types.v1.NodeReference;
import org.dataone.service.types.v1.Subject;
import org.opendap.d1.DatasetsDatabase.DAPD1DateParser;
import org.opendap.d1.DatasetsDatabase.DAPDatabaseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @brief A logging database for the DAP/D1 servlet.
 * 
 * This class is an interface to a SQL database that holds information about
 * each access to the DAP/D1 servlet using the D1 REST protocol for a D1 tier 1
 * member node. The database can be queried in a number of ways to access log
 * entries in accordance with the 'log()' function of the D1 MN Teir 1 API.
 *   
 * @author James Gallagher
 *
 */
public class LogDatabase {

	private static Logger log = LoggerFactory.getLogger(LogDatabase.class);
	
	private String dbName = "";
	private String nodeId = "";
	
	private Connection c = null;
	
	/**
	 * Open a connection to the log database. Note that the database is kept open until
	 * the object goes out of scope, when its finalize() method closes the connection.
	 * 
	 * @param name The name of the log database file
	 * @throws DAPDatabaseException 
	 * @exception Exception is thrown if the SQLite class is not found or the 
	 * connection cannot be opened.
	 * 
	 */
	public LogDatabase(String dbName, String nodeId) throws SQLException, ClassNotFoundException, DAPDatabaseException {
		this.nodeId = nodeId;
		this.dbName = dbName;
		
		try {
			// load the sqlite-JDBC driver using the current class loader
			Class.forName("org.sqlite.JDBC");
			c = DriverManager.getConnection("jdbc:sqlite:" + dbName);
		} catch (SQLException e) {
			log.error("Failed to open database ({}).", dbName);
			throw e;
		} catch (ClassNotFoundException e) {
			log.error("Failed to load the SQLite JDBC driver.");
			throw e;
		}
		    
		// if the DB is empty, build it
		if (!isValid()) {
			initTables();
			if (!isValid())
				throw new DAPDatabaseException("The database used for logging could not be opened.");
		}
		
		log.debug("Opened database successfully ({}).", dbName);
	}

	/** 
	 * Closes the DB connection 
	 * @note Not sure if this is needed... Connection might take care of it.
	 */
	protected void finalize( ) throws Throwable {
		c.close();
		log.debug("Database connection closed ({}).", dbName);
		super.finalize();
	}
	 
	/**
	 * Build the tables, assumes the DB is empty.
	 * 
	 * Note also that the foreign key constraints have been removed because
	 * SQLite on my computer does not seem to support them or the syntax is odd
	 * or something. See the SQLite docs at
	 * http://www.sqlite.org/foreignkeys.html for more info on this including to
	 * compile SQLite so that it supports foreign keys.
	 * 
	 * @throws SQLException Thrown if the tables already exist
	 */
	protected void initTables() throws SQLException {
		Statement stmt = c.createStatement();

		try {
			String sql = "CREATE TABLE Log "
					+ "(entryId		INTEGER PRIMARY KEY,"	// in SQLite 'entryId' becomes a synonym for 'ROWID'
					+ " PID		 	TEXT NOT NULL,"
					+ " ipAddress	TEXT NOT NULL,"
					+ " userAgent	TEXT NOT NULL,"
					+ " subject		TEXT NOT NULL,"
					+ " event	 	TEXT NOT NULL,"
					+ " dateLogged 	TEXT NOT NULL,"
					+ " nodeId 		TEXT NOT NULL)";
			stmt.executeUpdate(sql);
			
		} catch (SQLException e) {
			log.error("Failed to create new log database table ({}).", dbName);
			throw e;
		} finally {
			stmt.close();			
		}

		log.debug("Made log database table successfully ({}).", dbName);
	}
	
	/**
	 * Used by the unit tests
	 * @return the number of rows
	 * @throws SQLException
	 */
	public long count() throws SQLException {
		Statement stmt = c.createStatement();
		ResultSet rs = null;
		try {
			long rows = 0;
			rs = stmt.executeQuery("SELECT COUNT(*) FROM Log;");
			while (rs.next()) {
				rows = rs.getLong("COUNT(*)");
			}

			return rows;
			
		} catch (SQLException e) {
			log.error("Failed to count the Log table ({}): {}", dbName, e.getMessage());
			throw e;
		} finally {
			rs.close();
			stmt.close();
		}
	}

	/**
	 * Is this database valid?
	 *
	 * Checks to see that the database has a 'Log' table and only that. Does not
	 * do any other testing.
	 * 
	 * @return True if the database passes the test, false otherwise.
	 * @throws SQLException
	 */
	public boolean isValid() throws SQLException {
		final Set<String> tableNames 
			= new HashSet<String>(Arrays.asList("Log"));
		
		Statement stmt = c.createStatement();
		String sql = "SELECT name FROM sqlite_master WHERE type='table';";
		ResultSet rs = null;
		try {
			rs = stmt.executeQuery(sql);
			int count = 0;
			while (rs.next()) {
				count++;
				String name = rs.getString("name");
				if (!tableNames.contains(name)) {
					log.error("Database failed validity test; does not have table: " + name);
					return false;
				}
			}
			if (count != tableNames.size()) {
				log.error("Database failed validity test; does not have the required tables.");
				return false;
			}
			
			// All tests passed
			return true;
		} catch (SQLException e) {
			log.error("Error querying the log database ({}).", dbName);
			throw e;
		}
		finally {
			rs.close();
			stmt.close();
		}		
	}
	
	/**
	 * Add an entry  to the D1 logging database.
	 * 
	 * In addition to the parameters passed to this method, the D1 'subject' 
	 * (always 'public' for a Tier 1 servlet) and a unique identifier are 
	 * added to each entry. I added the 'public' subject so that the same 
	 * log DB could easily be extended to support a servlet that supports
	 * authentication. 
	 * 
	 * @param stmt The servlet's SQL Statement object
	 * @param PID
	 * @param ipAddress
	 * @param userAgent
	 * @param event
	 * 
	 * @throws SQLException
	 */
	public void addEntry(String PID, String ipAddress, String userAgent, String event) throws SQLException {
		
		//Statement stmt = c.createStatement();
		PreparedStatement stmt = null;
		// In this version of the DAP D1 servlet, the log record identifier is generated by the line 
		// below and the 'subject' field of the log record is always 'public' (because a Tier 1 node
		// does not support authentication). jhrg 7/15/14
		
		// NB: the 'EntryId' field is synonymous with SQLite's ROWID and is automatically incremented
		// with each insertion operation.
		
		String now8601 = DAPD1DateParser.DateToString(new Date());
		//String sql = "INSERT INTO Log (PID,ipAddress,userAgent,subject,event,dateLogged,nodeId) "
		//		+ "VALUES ('" + PID + "','" + ipAddress + "','" + userAgent + "','public','" + event + "','"
		//		+ now8601 + "','" + nodeId + "');";
		stmt = c.prepareStatement("INSERT INTO Log (PID,ipAddress,userAgent,subject,event,dateLogged,nodeId) VALUES (?, ?, ?, 'public', ?, ?, ?);");
		stmt.setString(1, PID);
		stmt.setString(2, ipAddress);
		stmt.setString(3, userAgent);
		stmt.setString(4, event);
		stmt.setString(5, now8601);
		stmt.setString(6, nodeId);
		
		//log.debug("SQL Statement: {}", sql);
		
		try {
			stmt.executeUpdate();
		} catch (SQLException e) {
			throw e;
		}
		finally {
			if (stmt != null)
				stmt.close();
		}
	}

	/**
	 * Dump the log database contents to stdout. This only dumps the fields common
	 * to all of the PIDs in the database (it does not show the DAP URL or 
	 * ORE document info). This is a debugging and diagnostic tool.
	 * 
	 * This is for testing.
	 * 
	 * @throws SQLException
	 */
	public void dump() throws SQLException {
		Statement stmt = c.createStatement();
		ResultSet rs = null;
		try {
			String sql = "SELECT * FROM Log ORDER BY ROWID;";
			rs = stmt.executeQuery(sql);
			while (rs.next()) {
				System.out.println("entryId = " + rs.getString("entryId"));
				System.out.println("PID = " + rs.getString("PID"));
				System.out.println("ipAddress = " + rs.getString("ipAddress"));
				System.out.println("userAgent = " + rs.getString("userAgent"));
				System.out.println("subject = " + rs.getString("subject"));
				System.out.println("event = " + rs.getString("event"));
				System.out.println("dateLogged = " + rs.getString("dateLogged"));
				System.out.println("nodeId = " + rs.getString("nodeId"));
				System.out.println();
			}

		} catch (SQLException e) {
			log.error("Failed to dump log database ({}).", dbName);
			throw e;
		} finally {
			rs.close();
			stmt.close();
		}
	}
		
	/**
	 * Extract entries from the log database.
	 * 
	 * This method takes a 'where clause' (which may be empty) and extracts count
	 * rows from the database, starting with row number 'start' where start uses
	 * zero-based indexing (the first row is '0').
	 * 
	 * @param where String literal spliced into the SQL query. May be empty.
	 * @param start First row number to return (zero-based indexing)
	 * @param count How many rows to return
	 * @return A D1 Log object that holds all of the matching log entries
	 * 
	 * @throws SQLException
	 * @throws DAPDatabaseException
	 */
	public Log getMatchingLogEntries(String where, int start, int count) throws SQLException, DAPDatabaseException {
		Statement stmt = c.createStatement();
		ResultSet rs = null;
		
		try {
			
			Log D1Log = new Log();
			
			D1Log.setStart(start);
			
			int rows = 0;
			rs = stmt.executeQuery("SELECT COUNT(*) FROM Log");
			while (rs.next()) {
				rows = rs.getInt(1);
			}
			D1Log.setTotal(rows);
			
			String querySQL = "SELECT * FROM Log " + where + " ORDER BY ROWID;";
			rs = stmt.executeQuery(querySQL);
			// rs.absolute(start+1); this does not work with SQLite

			int i = 0;
			while (rs.next()) {
				++i;
				if (i <= start)
					continue;
				if (i > start + count)
					break;

				LogEntry entry = new LogEntry();
				// TODO Can use index numbers; 1s indexing is used by JDBC; faster than names
				Long entryId = rs.getLong("entryId");
				entry.setEntryId(entryId.toString());
				
				Identifier identifier = new Identifier();
				identifier.setValue(rs.getString("PID"));
				entry.setIdentifier(identifier);
				
				entry.setIpAddress(rs.getString("ipAddress"));
				entry.setUserAgent(rs.getString("userAgent"));
				
				Subject subject = new Subject();
				subject.setValue(rs.getString("subject"));
				entry.setSubject(subject);
				
				Event event = Event.convert(rs.getString("event"));
				entry.setEvent(event);
				
				entry.setDateLogged(DAPD1DateParser.StringToDate(rs.getString("dateLogged")));
				
				NodeReference nodeIdentifier = new NodeReference();
				nodeIdentifier.setValue(rs.getString("nodeId"));
				entry.setNodeIdentifier(nodeIdentifier);
				
				// This takes the current row from the DB and stuffs it in the DataONE Log object.
				D1Log.addLogEntry(entry);
			}
			
			D1Log.setCount(i - start - 1);
			
			return D1Log;
			
		} catch (SQLException e) {
			log.error("Corrupt database (" + dbName + "): " + e.getMessage());
			throw e;
		} catch (ParseException e) {
			log.error("Corrupt database (" + dbName + "). Could not parse a Date/Time value: " + e.getMessage());
			throw new DAPDatabaseException(e.getMessage());
		} finally {
			rs.close();
			stmt.close();
		}
	}
	

}
