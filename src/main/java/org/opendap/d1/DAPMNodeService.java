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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.dataone.client.auth.CertificateManager;
import org.dataone.configuration.Settings;
import org.dataone.ore.ResourceMapFactory;
import org.dataone.service.exceptions.BaseException;
import org.dataone.service.exceptions.InsufficientResources;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.exceptions.SynchronizationFailed;
import org.dataone.service.mn.tier1.v1.MNCore;
import org.dataone.service.mn.tier1.v1.MNRead;
import org.dataone.service.types.v1.AccessPolicy;
import org.dataone.service.types.v1.AccessRule;
import org.dataone.service.types.v1.Checksum;
import org.dataone.service.types.v1.DescribeResponse;
import org.dataone.service.types.v1.Event;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.Log;
import org.dataone.service.types.v1.Node;
import org.dataone.service.types.v1.NodeReference;
import org.dataone.service.types.v1.NodeState;
import org.dataone.service.types.v1.NodeType;
import org.dataone.service.types.v1.ObjectFormatIdentifier;
import org.dataone.service.types.v1.ObjectInfo;
import org.dataone.service.types.v1.ObjectList;
import org.dataone.service.types.v1.Permission;
import org.dataone.service.types.v1.Ping;
import org.dataone.service.types.v1.ReplicationPolicy;
import org.dataone.service.types.v1.Schedule;
import org.dataone.service.types.v1.Service;
import org.dataone.service.types.v1.Services;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.Subject;
import org.dataone.service.types.v1.Synchronization;
import org.dataone.service.types.v1.SystemMetadata;
import org.dspace.foresite.ResourceMap;
import org.opendap.d1.DatasetsDatabase.DAPD1DateParser;
import org.opendap.d1.DatasetsDatabase.DAPDatabaseException;
import org.opendap.d1.DatasetsDatabase.DatasetMetadata;
import org.opendap.d1.DatasetsDatabase.DatasetsDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// This code does not support the optional Query interface of DataONE
// import org.dataone.service.mn.v1.MNQuery;
// import org.dataone.service.types.v1_1.QueryEngineDescription;
// import org.dataone.service.types.v1_1.QueryEngineList;

/** A DataONE Member Node (tier 1) for DAP servers
 * 
 * This DataONE Member Node implementation provides the MNCore and MNRead
 * APIs only. The optional Query and Views APIs are not (yet) supported.
 * 
 * Implements:
 * MNCore.ping()
 * MNCore.getLogRecords() - not yet
 * MNCore.getCapabilities()
 * MNRead.get()
 * MNRead.getSystemMetadata()
 * MNRead.describe()
 * MNRead.getChecksum()
 * MNRead.listObjects()
 * MNRead.synchronizationFailed() - not yet
 * 
 * @note This class could extend D1NodeService to pick up that abstract class'
 * ping(), etc., methods but it assume the metacat RDB is used for a number
 * of features.
 * 
 * @author James Gallagher
 *
 */
public class DAPMNodeService implements MNCore, MNRead {

	private static Logger log = LoggerFactory.getLogger(DAPMNodeService.class);

	private static DAPMNodeService singleton = null;
	
	/// For logging the operations
	protected HttpServletRequest request;
	/// An open connection to the database that holds the dataset info
	protected DatasetsDatabase db;
	// An open connection to the Log database
	protected LogDatabase logDb;

	/**
	 * out-of-band session object to be used when not passed in as a method
	 * parameter
	 */
	protected Session session;

	/**
	 * retrieve the out-of-band session
	 * 
	 * @return
	 */
	public Session getSession() {
		return session;
	}

	/**
	 * Set the out-of-band session
	 * 
	 * @param session
	 */
	public void setSession(Session session) {
		this.session = session;
	}

	/**
	 * Singleton accessor to get an instance of MNodeService. Assume that the 
	 * request and db objects are valid.
	 * 
	 * @return instance - the instance of MNodeService
	 * @throws DAPDatabaseException 
	 */
	public synchronized static DAPMNodeService getInstance(HttpServletRequest request, DatasetsDatabase db, LogDatabase logDb) {
		if (singleton == null) {
			singleton = new DAPMNodeService(request, db, logDb);
		}
		return singleton;
	}

	/**
	 * Constructor, private for singleton access.
	 */
	private DAPMNodeService(HttpServletRequest request, DatasetsDatabase db, LogDatabase logDb) {
		log = LoggerFactory.getLogger(DAPMNodeService.class);

		this.request = request;
		this.db = db;
		this.logDb = logDb;

		// set the Member Node certificate file location
		CertificateManager.getInstance().setCertificateLocation(Settings.getConfiguration().getString("D1Client.certificate.file"));
	}

	/**
	 * Grab the system metadata info and repackage it for the describe() response.
	 *  
	 * @see org.dataone.service.mn.tier1.v1.MNRead#describe(org.dataone.service.types.v1.Identifier)
	 */
	// @Override
	public DescribeResponse describe(Identifier pid) throws InvalidToken,
			NotAuthorized, NotImplemented, ServiceFailure, NotFound {

		if (!db.isInMetadata(pid.getValue()))
			throw new NotFound("1380", "The PID '" + pid.getValue() + "' was not found on this server.");
		
		try {
			SystemMetadata sysmeta = getSystemMetadata(pid);
			return new DescribeResponse(sysmeta.getFormatId(), sysmeta.getSize(),
					sysmeta.getDateSysMetadataModified(), sysmeta.getChecksum(), sysmeta.getSerialVersion());

		} catch (ServiceFailure e) {
			throw new ServiceFailure("1390", e.getMessage());
		}
	}

	/**
	 * Return the SDO, SMO or ORE document that matches the given D1/DAP server
	 * PID. Note that this is used for both /object and /replica calls.
	 * 
	 * @param pid The D1 Persistent Identifier for the local object
	 * @return An InputStream; read the object from this.
	 * @see org.dataone.service.mn.tier1.v1.MNRead#get()
	 */
	@Override
	public InputStream get(Identifier pid) throws InvalidToken, NotAuthorized,
			NotImplemented, ServiceFailure, NotFound, InsufficientResources {
		// Query the database for the PID. If it is a SDO or SMO, then we must
		// access the DAP server and return the streamed object via the InputStream.
		// if the PID references an ORE document, we must build the ORE doc and 
		// return it.
		
		if (!db.isInMetadata(pid.getValue()))
			throw new NotFound("1020", "The PID '" + pid.getValue() + "' was not found on this server.");
		
		try {
			InputStream in = null;
			
			// Anything other than an ORE doc must be DAP URL for this server.
			if (db.isDAPURL(pid.getValue())) {
				// For a DAP URL (e.g., it's a .nc or .iso URL), dereference and 
				// return the InputStream
				HttpClient client = new DefaultHttpClient();
				HttpGet request = new HttpGet(db.getDAPURL(pid.getValue()));
				HttpResponse response = client.execute(request);

				// Get the response
				in = response.getEntity().getContent();
			}
			else {
				List<String> ids = db.getIdentifiersForORE(pid.getValue());
				
				Identifier smoId = new Identifier();
				smoId.setValue(ids.get(0));

				List<Identifier> dataObjects = new Vector<Identifier>();
				Identifier sdoId = new Identifier();
				sdoId.setValue(ids.get(1));
				dataObjects.add(sdoId);
				
				Map<Identifier, List<Identifier>> idMap = new HashMap<Identifier, List<Identifier>>();
				idMap.put(smoId, dataObjects);
				
				ResourceMap rm = ResourceMapFactory.getInstance().createResourceMap(pid, idMap);
				String resourceMapXML = ResourceMapFactory.getInstance().serializeResourceMap(rm);
				in = new ByteArrayInputStream(resourceMapXML.getBytes());
			}
			
			if (in == null)		
				throw new NotFound("1020", "The PID '" + pid.getValue() + "' was not found.");
			
			return in;

		} catch (Exception e) {
            log.error(e.getMessage());
            throw new ServiceFailure("1030", e.getMessage());
		}
	}

	/**
	 * Lookup the checksum for the given PID. If the algorithm used does not
	 * match the one given in the arg list, throw an InvalidRequest.
	 * 
	 * @param pid D1 PID
	 * @param algorithm The checksum to use - must be SHA-1.
	 *  
	 * @see org.dataone.service.mn.tier1.v1.MNRead#getChecksum(org.dataone.service.types.v1.Identifier, java.lang.String)
	 */
	// @Override
	public Checksum getChecksum(Identifier pid, String algorithm)
			throws InvalidRequest, InvalidToken, NotAuthorized, NotImplemented,
			ServiceFailure, NotFound {
		
		if (!db.isInMetadata(pid.getValue()))
			throw new NotFound("1420", "The PID '" + pid.getValue() + "' was not found on this server.");
		
		Checksum checksum = new Checksum();
		// Looks fancy, but I only plan to support SHA-1. 6/4/14
		try {
			String algUsed = db.getAlgorithm(pid.getValue());
			if (!algUsed.equalsIgnoreCase(algorithm))
				throw new InvalidRequest("1402", "This DataONE Member Node only supports the SHA-1 checksum algorithm");
			checksum.setAlgorithm(algUsed);
			checksum.setValue(db.getChecksum(pid.getValue()));
		} catch (SQLException e) {
			throw new ServiceFailure("1410", e.getMessage());
		} catch (DAPDatabaseException e) {
			throw new ServiceFailure("1410", e.getMessage());
		}

		return checksum;
	}

	/**
	 * In the DAP D1 servlet, get(PID) is used for both the /object and /replica
	 * calls. This should never be called. It has to be defined because it's part
	 * of the MNRead interface.
	 * 
	 * @see org.dataone.service.mn.tier1.v1.MNRead#getReplica(org.dataone.service.types.v1.Identifier)
	 */
	// @Override
	public InputStream getReplica(Identifier pid) throws ServiceFailure {

		throw new ServiceFailure("2181", "This internal method should never be called.");
	}
		
	/**
	 * Build a populated instance of the DataONE SystemMetadata object and
	 * return it. This method makes some assumptions about values for many of
	 * the fields of the object that are specific to DAP and the idea that
	 * a DAP server is providing the values for the SDO and SMO.
	 * 
	 * TODO Replace the set of database calls with one call.
	 * 
	 * @param pid The DataONE PID
	 * @return an instance of SystemMetadata
	 * @see org.dataone.service.mn.tier1.v1.MNRead#getSystemMetadata(org.dataone.service.types.v1.Identifier)
	 */
	public SystemMetadata getSystemMetadata(Identifier pid)
			throws InvalidToken, NotAuthorized, NotImplemented, ServiceFailure,
			NotFound {
		
		if (!db.isInMetadata(pid.getValue()))
			throw new NotFound("1060", "The PID '" + pid.getValue() + "' was not found on this server.");
		
		try {
			SystemMetadata sm = new SystemMetadata();

			sm.setIdentifier(pid);
			
			ObjectFormatIdentifier formatId = new ObjectFormatIdentifier();
			formatId.setValue(db.getFormatId(pid.getValue()));
			sm.setFormatId(formatId);

			sm.setSerialVersion(db.getSerialNumber(pid.getValue()));
			
			sm.setSize(new BigInteger(db.getSize(pid.getValue())));
			
			Checksum checksum = new Checksum();
			// Looks fancy, but I only plan to support SHA-1. 6/4/14
			checksum.setAlgorithm(db.getAlgorithm(pid.getValue()));
			checksum.setValue(db.getChecksum(pid.getValue()));
			sm.setChecksum(checksum);
			
			// Basic policies: The node is the 'submitter' and 'RightsHolder' and 
			// can READ, WRITE and CHANGE_PERMISSION on the stuff. The 'public:' can READ.
			// Note that 'Submitter' is optional while RightsHolder is required.
			Subject submitter = new Subject();
			String nodeId = Settings.getConfiguration().getString("org.opendap.d1.nodeId");
			submitter.setValue(nodeId);	// nodeId is also used as the origin/auth node below
			sm.setSubmitter(submitter);
			
			sm.setRightsHolder(submitter);
			
			// Everything from here down is optional
			AccessRule submitterRule = new AccessRule();
			submitterRule.addSubject(submitter);
			submitterRule.addPermission(Permission.READ);
			submitterRule.addPermission(Permission.WRITE);
			submitterRule.addPermission(Permission.CHANGE_PERMISSION);
			
			Subject pub = new Subject();
			pub.setValue(Settings.getConfiguration().getString("org.opendap.d1.subject")); // "public:"
			AccessRule publicRule = new AccessRule();
			publicRule.addSubject(pub);
			publicRule.addPermission(Permission.READ);
			
			AccessPolicy ap = new AccessPolicy();
			ap.addAllow(submitterRule);
			ap.addAllow(publicRule);
			sm.setAccessPolicy(ap);
			
			ReplicationPolicy rp = new ReplicationPolicy();
			boolean replicate = false;
			if (Settings.getConfiguration().getString("org.opendap.d1.nodeReplicate").equals("true"))
				replicate = true;
			rp.setReplicationAllowed(replicate);
			// We can set a number of limits on how much is replicated and who does the 
			// replication, etc., but for now, if a site wants to replicate content, let
			// them. jhrg 6/10/14
			sm.setReplicationPolicy(rp);
			
			Date date = db.getDateSysmetaModified(pid.getValue());
			sm.setDateSysMetadataModified(date);
			sm.setDateUploaded(date);
			
			NodeReference nr = new NodeReference();
			nr.setValue(nodeId);	// read from the properties above
			sm.setOriginMemberNode(nr);
			sm.setAuthoritativeMemberNode(nr);
			
			// There is a Replica object in the D1 classes and a matching field for
			// the SystemMetadata object/response. I'm ignoring it because replication
			// is not allowed by default for this servlet. 6/4/14
			
			return sm;
		} catch (DAPDatabaseException e) {
			throw new ServiceFailure("1090", e.getMessage());
		} catch (SQLException e) {
			throw new ServiceFailure("1090", e.getMessage());
		}
	}

	/**
	 * Return information about PIDs. This queries the database for information about
	 * the PIDs this node knows about.
	 * 
	 * @see org.dataone.service.mn.tier1.v1.MNRead#listObjects(java.util.Date, java.util.Date, org.dataone.service.types.v1.ObjectFormatIdentifier, java.lang.Boolean, java.lang.Integer, java.lang.Integer)
	 */
	// @Override
	public ObjectList listObjects(Date fromDate, Date toDate, ObjectFormatIdentifier format, Boolean ignored,
			Integer start, Integer count) throws InvalidRequest, InvalidToken, NotAuthorized, NotImplemented, 
			ServiceFailure {
		
		// Take all the params and build up a 'where' clause that will select just what the 
		// client wants.
		String where = buildObjectsWhereClause(fromDate, toDate, format);
		log.debug("In listObjects; where clause: " + where);
		
		try {
			// This returns just 'count' entries starting with zero-based entry 'start'
			List<DatasetMetadata> dmv = db.getAllMetadata(where, start, count);
			
			ObjectList ol = new ObjectList();
			ol.setStart(start);
			ol.setCount(dmv.size());
			ol.setTotal(db.count(where));
			for (DatasetMetadata dm: dmv) {
				ObjectInfo oi = new ObjectInfo();
				
				Identifier id = new Identifier();
				id.setValue(dm.getPID());
				oi.setIdentifier(id);
				
				ObjectFormatIdentifier formatId = new ObjectFormatIdentifier();
				formatId.setValue(dm.getFormat());
				oi.setFormatId(formatId);

				Checksum checksum = new Checksum();
				checksum.setAlgorithm(dm.getAlgorithm());
				checksum.setValue(dm.getChecksum());
				oi.setChecksum(checksum);
				
				oi.setDateSysMetadataModified(dm.getDateSystemMetadataModified());
				
				oi.setSize(dm.getSize());
				
				ol.addObjectInfo(oi);	
			}
			
			return ol;
			
		} catch (SQLException e) {
			throw new ServiceFailure("1580", e.getMessage());
		} catch (DAPDatabaseException e) {
			throw new ServiceFailure("1580", e.getMessage());
		}
	}

	/**
	 * Build a SQL 'where clause' that can be used to select just what the client wants.
	 * 
	 * @param fromDate Only return stuff stating at this date
	 * @param toDate ... and up to (but not including) this date
	 * @param format ... and only this format
	 * @param replicas but ignore this since we only store stuff for which we are an authoritative source
	 * 
	 * @return The WHERE clause a a string.
	 */
	private String buildObjectsWhereClause(Date fromDate, Date toDate, ObjectFormatIdentifier format) {
		
		String and = "";
		String where = "";
		if (fromDate != null) {
			where += "dateAdded >= '" + DAPD1DateParser.DateToString(fromDate) + "'";
			and = " and ";
		}
		
		if (toDate != null) {
			where += and + "dateAdded < '" + DAPD1DateParser.DateToString(toDate) + "'";
			and = " and ";
		}
		
		if (format != null) {
			where += and + "format = '" + format.getValue() + "'";
			// and = " and";
		}

		// Ignore replicas for now.
		if (!where.isEmpty())
			where = "where " + where;
		
		return where;
	}

	private String buildLogEntriesWhereClause(Date fromDate, Date toDate, Event event, String idFilter) {
		
		String and = "";
		String where = "";
		if (fromDate != null) {
			where += "dateLogged >= '" + DAPD1DateParser.DateToString(fromDate) + "'";
			and = " and ";
		}
		
		if (toDate != null) {
			where += and + "dateLogged < '" + DAPD1DateParser.DateToString(toDate) + "'";
			and = " and ";
		}
		
		if (event != null) {
			where += and + "event = '" + event.toString() + "'";
			and = " and";
		}

		if (idFilter != null) {
			where += and + "PID like '" + idFilter + "%'";			
		}
		
		if (!where.isEmpty())
			where = "where " + where;
		
		return where;
	}

	/* (non-Javadoc)
	 * @see org.dataone.service.mn.tier1.v1.MNRead#synchronizationFailed(org.dataone.service.exceptions.SynchronizationFailed)
	 */
	// @Override
	public boolean synchronizationFailed(SynchronizationFailed arg0)
			throws InvalidToken, NotAuthorized, NotImplemented, ServiceFailure {
		// TODO Auto-generated method stub
		return false;
	}

	/**
	 * Read configuration parameters from opendap.properties and build a 
	 * Node object. Note that this calls ping()
	 * 
	 * @return a Node object
	 * 
	 * @see org.dataone.service.mn.tier1.v1.MNCore#getCapabilities()
	 */
	public Node getCapabilities() throws NotImplemented, ServiceFailure {

        String nodeName = null;
        String nodeId = null;
        String subject = null;
        String contactSubject = null;
        String nodeDesc = null;
        String nodeTypeString = null;
        NodeType nodeType = null;
        String mnCoreServiceVersion = null;
        String mnReadServiceVersion = null;
  
        boolean nodeSynchronize = false;
        boolean nodeReplicate = false;
        boolean mnCoreServiceAvailable = false;
        boolean mnReadServiceAvailable = false;
        
        try {
            // get the properties of the node based on configuration information
            nodeName = Settings.getConfiguration().getString("org.opendap.d1.nodeName");
            nodeId = Settings.getConfiguration().getString("org.opendap.d1.nodeId");
            subject = Settings.getConfiguration().getString("org.opendap.d1.subject");
            contactSubject = Settings.getConfiguration().getString("org.opendap.d1.contactSubject");
            nodeDesc = Settings.getConfiguration().getString("org.opendap.d1.nodeDescription");
            nodeTypeString = Settings.getConfiguration().getString("org.opendap.d1.nodeType");
            nodeType = NodeType.convert(nodeTypeString);
            
            nodeSynchronize = Settings.getConfiguration().getBoolean("org.opendap.d1.nodeSynchronize");
            nodeReplicate = Settings.getConfiguration().getBoolean("org.opendap.d1.nodeReplicate");

            mnCoreServiceVersion = Settings.getConfiguration().getString("org.opendap.d1.mnCore.serviceVersion");
            mnReadServiceVersion = Settings.getConfiguration().getString("org.opendap.d1.mnRead.serviceVersion");

            mnCoreServiceAvailable = Settings.getConfiguration().getBoolean("org.opendap.d1.mnCore.serviceAvailable");
            mnReadServiceAvailable = Settings.getConfiguration().getBoolean("org.opendap.d1.mnRead.serviceAvailable");

            // Set the properties of the node based on configuration information and
            // calls to current status methods
            String serviceName = Settings.getConfiguration().getString("org.opendap.d1.serviceName");
            
            Node node = new Node();
            node.setBaseURL(serviceName + "/" + nodeTypeString + "/");
            node.setDescription(nodeDesc);

            // set the node's health information
            node.setState(NodeState.UP);
            
            // set the ping response to the current value
            Ping canPing = new Ping();
            canPing.setSuccess(false);
            try {
            	Date pingDate = ping();
                canPing.setSuccess(pingDate != null);
            } catch (BaseException e) {
                e.printStackTrace();
                // guess it can't be pinged
            }
            
            node.setPing(canPing);

            NodeReference identifier = new NodeReference();
            identifier.setValue(nodeId);
            node.setIdentifier(identifier);
            Subject s = new Subject();
            s.setValue(subject);
            node.addSubject(s);
            Subject contact = new Subject();
            contact.setValue(contactSubject);
            node.addContactSubject(contact);
            node.setName(nodeName);
            node.setReplicate(nodeReplicate);
            node.setSynchronize(nodeSynchronize);

            // services: MNAuthorization, MNCore
            Services services = new Services();

            Service sMNCore = new Service();
            sMNCore.setName("MNCore");
            sMNCore.setVersion(mnCoreServiceVersion);
            sMNCore.setAvailable(mnCoreServiceAvailable);

            Service sMNRead = new Service();
            sMNRead.setName("MNRead");
            sMNRead.setVersion(mnReadServiceVersion);
            sMNRead.setAvailable(mnReadServiceAvailable);

            services.addService(sMNRead);
            services.addService(sMNCore);
            
            node.setServices(services);

            // Set the schedule for synchronization
            Synchronization synchronization = new Synchronization();
            Schedule schedule = new Schedule();
            schedule.setYear(Settings.getConfiguration().getString("org.opendap.d1.nodeSynchronization.schedule.year"));
            schedule.setMon(Settings.getConfiguration().getString("org.opendap.d1.nodeSynchronization.schedule.mon"));
            schedule.setMday(Settings.getConfiguration().getString("org.opendap.d1.nodeSynchronization.schedule.mday"));
            schedule.setWday(Settings.getConfiguration().getString("org.opendap.d1.nodeSynchronization.schedule.wday"));
            schedule.setHour(Settings.getConfiguration().getString("org.opendap.d1.nodeSynchronization.schedule.hour"));
            schedule.setMin(Settings.getConfiguration().getString("org.opendap.d1.nodeSynchronization.schedule.min"));
            schedule.setSec(Settings.getConfiguration().getString("org.opendap.d1.nodeSynchronization.schedule.sec"));
            synchronization.setSchedule(schedule);
            
            Date now = new Date();
            synchronization.setLastHarvested(now);
            synchronization.setLastCompleteHarvest(now);
            node.setSynchronization(synchronization);

            node.setType(nodeType);
            return node;

        } catch (Throwable e) {
            String msg = "MNodeService.getCapabilities(): " + "property not found: " + e.getMessage();
            log.error(msg);
            throw new ServiceFailure("2162", msg);
        } 
	}

	/**
	 * Return log records.
	 * 
	 * Use the log database to extract log records for access to the server.
	 * 
	 * @return A D1 Log object with the requested Log Entries.
	 */
	// @Override
	public Log getLogRecords(Date fromDate, Date toDate, Event event, String idFilter, Integer start, Integer count) 
			throws InvalidRequest, InvalidToken, NotAuthorized, NotImplemented, ServiceFailure {

		String where = buildLogEntriesWhereClause(fromDate, toDate, event, idFilter);
		log.debug("In listObjects; where clause: " + where);

		try {
			return logDb.getMatchingLogEntries(where, start, count);
		} catch (Exception e) {
			throw new ServiceFailure("1490", "Encountered an Exception while accessing the log: " + e.getMessage());
		}
	}

	/** 
	 * Handle the ping() call of the MNCore API.
	 * 
	 * To test if the server is working, dereference the base URL as set
	 * in the opendap.properties file and see if that returns a HTTP status
	 * code of 200. No redirects allowed.
	 * 
	 * @return Today's date/time if the underlying DAP server associated with
	 * this D1 Member Node is working, null otherwise.
	 * 
	 * @see org.dataone.service.mn.tier1.v1.MNCore#ping()
	 */
	// @Override
	public Date ping() throws NotImplemented, ServiceFailure, InsufficientResources {
		log.trace("In ping(); DAPServerBaseURL: " + Settings.getConfiguration().getString("org.opendap.d1.DAPServerBaseURL"));
		
		try {
			URL baseURL = new URL(Settings.getConfiguration().getString("org.opendap.d1.DAPServerBaseURL"));
			HttpURLConnection URLConnection = (HttpURLConnection) baseURL.openConnection();
			if (URLConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
				return null;
			}
		} catch (MalformedURLException e) {
	      	ServiceFailure sf = new ServiceFailure("2042", e.getMessage());
	      	sf.initCause(e);
	        throw sf;
		} catch (IOException e) {
	      	ServiceFailure sf = new ServiceFailure("2042", e.getMessage());
	      	sf.initCause(e);
	        throw sf;
		}
	
		return Calendar.getInstance().getTime();
	}

	// These are all the deprecated methods. Eclipse wants to see them implemented
	// because MNCore and MNRead are interfaces. jhrg 5/9/14
	
	// @Override
	@Deprecated
	public Checksum getChecksum(Session arg0, Identifier arg1, String arg2)
			throws InvalidRequest, InvalidToken, NotAuthorized, NotImplemented, ServiceFailure, NotFound {
		throw new NotImplemented("2041", "DAPMNodeService does not implement the deprecated MNCore and MNRead methods.");
	}

	// @Override
	@Deprecated
	public InputStream getReplica(Session arg0, Identifier arg1)
			throws InvalidToken, NotAuthorized, NotImplemented, ServiceFailure, NotFound, InsufficientResources {
		throw new NotImplemented("2041", "DAPMNodeService does not implement the deprecated MNCore and MNRead methods.");
	}

	// @Override
	@Deprecated
	public ObjectList listObjects(Session arg0, Date arg1, Date arg2, ObjectFormatIdentifier arg3, Boolean arg4, Integer arg5, Integer arg6)
			throws InvalidRequest, InvalidToken, NotAuthorized, NotImplemented, ServiceFailure {
		throw new NotImplemented("2041", "DAPMNodeService does not implement the deprecated MNCore and MNRead methods.");
	}

	// @Override
	@Deprecated
	public boolean synchronizationFailed(Session arg0, SynchronizationFailed arg1) 
			throws InvalidToken, NotAuthorized, NotImplemented, ServiceFailure {
		throw new NotImplemented("2041", "DAPMNodeService does not implement the deprecated MNCore and MNRead methods.");
	}

	// @Override
	@Deprecated
	public DescribeResponse describe(Session arg0, Identifier arg1)
			throws InvalidToken, NotAuthorized, NotImplemented, ServiceFailure, NotFound {
		throw new NotImplemented("2041", "DAPMNodeService does not implement the deprecated MNCore and MNRead methods.");
	}

	// @Override
	@Deprecated
	public InputStream get(Session arg0, Identifier arg1) throws InvalidToken, NotAuthorized, NotImplemented, ServiceFailure, NotFound, InsufficientResources {
		throw new NotImplemented("2041", "DAPMNodeService does not implement the deprecated MNCore and MNRead methods.");
	}

	// @Override
	@Deprecated
	public SystemMetadata getSystemMetadata(Session arg0, Identifier arg1)
			throws InvalidToken, NotAuthorized, NotImplemented, ServiceFailure, NotFound {
		throw new NotImplemented("2041", "DAPMNodeService does not implement the deprecated MNCore and MNRead methods.");
	}

	// @Override
	@Deprecated
	public Log getLogRecords(Session arg0, Date arg1, Date arg2, Event arg3, String arg4, Integer arg5, Integer arg6) 
			throws InvalidRequest, InvalidToken, NotAuthorized, NotImplemented, ServiceFailure {
		throw new NotImplemented("2041", "DAPMNodeService does not implement the deprecated MNCore and MNRead methods.");
	}
}
