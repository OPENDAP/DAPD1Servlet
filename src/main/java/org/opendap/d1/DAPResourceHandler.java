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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.io.IOUtils;
import org.dataone.client.auth.CertificateManager;
import org.dataone.configuration.Settings;
import org.dataone.mimemultipart.MultipartRequest;
import org.dataone.mimemultipart.MultipartRequestResolver;
import org.dataone.service.exceptions.BaseException;
import org.dataone.service.exceptions.InsufficientResources;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.exceptions.SynchronizationFailed;
import org.dataone.service.types.v1.Checksum;
import org.dataone.service.types.v1.DescribeResponse;
import org.dataone.service.types.v1.Event;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.Log;
import org.dataone.service.types.v1.Node;
import org.dataone.service.types.v1.ObjectFormatIdentifier;
import org.dataone.service.types.v1.ObjectList;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.SystemMetadata;
import org.dataone.service.util.Constants;
import org.dataone.service.util.DateTimeMarshaller;
import org.dataone.service.util.ExceptionHandler;
import org.dataone.service.util.TypeMarshaller;
import org.jibx.runtime.JiBXException;
import org.opendap.d1.DatasetsDatabase.DAPD1DateParser;
import org.opendap.d1.DatasetsDatabase.DAPDatabaseException;
import org.opendap.d1.DatasetsDatabase.DatasetsDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

/**
 * @brief Handle GET, POST and HEAD requests for the DAP/D1 servlet.
 * 
 * MN REST service implementation handler
 * 
 * MNCore -- Partly 
 * ping() - GET /d1/mn/monitor/v1/ping (done)
 * log() - GET /d1/mn/v1/log (done)
 * getCapabilities() - GET /d1/mn/ and /d1/mn/v1/node (done)
 * 
 * MNRead -- Partly 
 * get() - GET /d1/mn/v1/object/PID (done)
 * getSystemMetadata() - GET /d1/mn/v1/meta/PID (done)
 * getReplica() - GET /replica/PID (done)
 * describe() - HEAD /d1/mn/v1/object/PID (done)
 * getChecksum() - GET /d1/mn/v1/checksum/PID (done)
 * listObjects() - GET /d1/mn/v1/object (done)
 * synchronizationFailed() - POST /d1/mn/v1/error
 * 
 * @author James Gallagher, after Ben Leinfelder
 */

public class DAPResourceHandler {

	/** HTTP Verb GET */
	public static final byte GET = 1;
	/** HTTP Verb POST; only used by this servlet for sync failed. */
	public static final byte POST = 2;
	/** HTTP Verb HEAD; only for the describe method */
	public static final byte HEAD = 5;

	// API Resources
	private static final String RESOURCE_OBJECTS = "object";
	private static final String RESOURCE_CHECKSUM = "checksum";
	private static final String RESOURCE_REPLICA = "replica";
	
	private static final String RESOURCE_META = "meta";
	private static final String RESOURCE_LOG = "log";
	
	private static final String RESOURCE_MONITOR = "monitor";
	private static final String RESOURCE_NODE = "node";
	private static final String RESOURCE_ERROR = "error";
	
	private static final String API_VERSION = "v1/";	// needs the trailing slash

	// The default number of responses for the listObjects() call
	private static int DEFAULT_COUNT = 1000;
	
	private static String OPENDAP_PROPERTIES = "opendap.properties";
	
	private static Logger log = LoggerFactory.getLogger(DAPResourceHandler.class);

	private ServletContext servletContext;

	protected HttpServletRequest request;
	protected HttpServletResponse response;

	/// An open connection to the database that holds the dataset info
	protected DatasetsDatabase db;

	/// An open connection to the log db
	protected LogDatabase logDb;
	
	/// The query string params
	//protected Hashtable<String, String[]> params;
	
	// D1 certificate-based authentication
	protected Session session;
	
	/* There are a number of ways to improve the performance of this
	 * servlet. One is to pool the two database connections. The second
	 * is to use a shared executor as illustrated below.  Explore these
	 * if we get the opportunity to optimize the code. jhrg 7/22/14
	 */
	/*
    // shared executor
	private static ExecutorService executor = null;

	static {
		// use a shared executor service with nThreads == one less than available processors
    	int availableProcessors = Runtime.getRuntime().availableProcessors();
        int nThreads = availableProcessors * 1;
        nThreads--;
        nThreads = Math.max(1, nThreads);
    	executor = Executors.newFixedThreadPool(nThreads);	
	}
	*/
	
	/*
    // run it in a thread to avoid connection timeout
    Runnable runner = new Runnable() {
		@Override
		public void run() {
			try {
		        MNodeService.getInstance(request).replicate(session, sysmeta, sourceNode);
			} catch (Exception e) {
				logMetacat.error("Error running replication: " + e.getMessage(), e);
				throw new RuntimeException(e.getMessage(), e);
			}
		}
	};
	// submit the task, and that's it
	executor.submit(runner);
    */

	/**
	 * @brief Initializes new instance by setting servlet context,request and response.
	 * 
	 * This is called by DAPRestServlet.createHandler(). The resulting
	 * instance is used 'handle' the GET, POST or HEAD request.
	 */
	public DAPResourceHandler(ServletContext servletContext, HttpServletRequest request, HttpServletResponse response)
			throws DAPDatabaseException {
		
		this.servletContext = servletContext;
		this.request = request;
		this.response = response;
		
		try {
			Settings.augmentConfiguration(OPENDAP_PROPERTIES);
		}
		catch (ConfigurationException ce) {
			log.error("Failed to read the config file: {}", OPENDAP_PROPERTIES);
		}

		String dbName = Settings.getConfiguration().getString("org.opendap.d1.DatasetsDatabaseName");
		log.debug("in object (dbName: {})", dbName);

		try {
			db = new DatasetsDatabase(dbName);
			if (!db.isValid())
				throw new DAPDatabaseException("The database is not valid (" + dbName + ").");
		} catch (SQLException e) {
			throw new DAPDatabaseException("The database is not valid (" + dbName + "): " + e.getMessage());
		} catch (ClassNotFoundException e) {
			throw new DAPDatabaseException("The database is not valid (" + dbName + "): " + e.getMessage());
		}
		
		String logDbName = Settings.getConfiguration().getString("org.opendap.d1.LogDatabaseName");
		String nodeId = Settings.getConfiguration().getString("org.opendap.d1.nodeId");
		log.debug("in object (Log database name: {}; nodeId: {})", logDbName, nodeId);
		try {
			logDb = new LogDatabase(logDbName, nodeId);
			if (!logDb.isValid())
				throw new DAPDatabaseException("The database is not valid (" + logDbName + ").");
		} catch (SQLException e) {
			throw new DAPDatabaseException("The database is not valid (" + logDbName + "): " + e.getMessage());
		} catch (ClassNotFoundException e) {
			throw new DAPDatabaseException("The database is not valid (" + logDbName + "): " + e.getMessage());
		}

	}

	/**
	 * This function is called from the REST API servlet and handles each request
	 * 
	 * @param httpVerb (GET, HEAD, POST)
	 */
	public void handle(byte httpVerb) {

		try {
			// Set the Session member; null indicates no session info
			// FIXME getSession();

			try {
				// get the resource
				String resource = request.getPathInfo();

				log.debug("handling verb {} request with resource '{}'", httpVerb, resource);

				// In the web.xml for the DAPRestServlet, I set the url pattern
				// like this: <url-pattern>/d1/mn/*</url-pattern> which means
				// that the leading '/d1/mn/' is removed by the servlet container.
				// Since this servlet implements only the 'v1' API, I've hardcoded
				// that value here. It could be read from the config file using
				// the org.opendap.d1.mnCore.serviceVersion and mnRead...
				// properties. jhrg 5/20/14
				resource = parseTrailing(resource, API_VERSION);

				log.debug("processed resource: '" + resource + "'");

				// default to node info
				if (resource == null || resource.equals("")) {
					resource = RESOURCE_NODE;
				}

				// get the rest of the path info
				String extra = null;
				boolean status = false;

				if (resource.startsWith(RESOURCE_NODE)) {
					log.debug("Using resource '" + RESOURCE_NODE + "'");
					
					if (httpVerb == GET) {
						// node (aka getCapabilities) response. The method uses
						// the output stream to serialize the result and throws
						// an
						// exception if there's a problem.
						sendNodeResponse();
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_META)) {
					log.debug("Using resource '" + RESOURCE_META + "'");

					if (httpVerb == GET) {
						// after the command
						extra = parseTrailing(resource, RESOURCE_META);
						// NB: When Tomcat is configured to allow URL encoded paths into the servlets,
						// it does the decoding before  making the doGet(), ..., calls.
						// However, here's code to decode the PID, if it's ever needed. jhrg 6/13/14
						// logDAP.debug("PID before decoding: " + parseTrailing(resource, RESOURCE_META));
						// extra = new URI(parseTrailing(resource, RESOURCE_META)).getPath();
						// logDAP.debug("PID after decoding: " + extra);
						
						sendSysmetaResponse(extra);
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_OBJECTS)) {
					// This is the get() call which returns SDOs and SMOs
					// or the describe() call for the same depending on the
					// HTTP verb (GET or HEAD)
					log.debug("Using resource '" + RESOURCE_OBJECTS + "'");
					// 'extra' is text that follows the command in the URL's path.
					extra = parseTrailing(resource, RESOURCE_OBJECTS);
					log.debug("objectId: " + extra);
					log.debug("verb:" + httpVerb);

					if (httpVerb == GET) {
						if (extra == null || extra.isEmpty()) {
							Hashtable<String, String[]>params = new Hashtable<String, String[]>();
							initParams(params);

							sendListObjects(params);
						}
						else {
							// In the line that follows, I cannot get Event.READ to work but I know
							// that simple strings work.
							logDb.addEntry(extra, request.getRemoteAddr(), request.getHeader("user-agent"), 
									Constants.SUBJECT_PUBLIC, "read");
							sendObject(extra);
						}
						status = true;
					} else if (httpVerb == HEAD) {
						sendDescribeObject(extra);
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_LOG)) {
					log.debug("Using resource '" + RESOURCE_LOG + "'");
					// handle log events
					if (httpVerb == GET) {
						Hashtable<String, String[]>params = new Hashtable<String, String[]>();
						initParams(params);

						sendLogEntries(params);
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_CHECKSUM)) {
					log.debug("Using resource '" + RESOURCE_CHECKSUM + "'");
					// handle checksum requests
					if (httpVerb == GET) {
						// 'extra' is text that follows the command in the URL's path.
						extra = parseTrailing(resource, RESOURCE_CHECKSUM);
						String algorithm = "SHA-1";
						sendChecksum(extra, algorithm);
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_REPLICA)) {
					log.debug("Using resource '" + RESOURCE_REPLICA + "'");
					// handle replica requests
					if (httpVerb == GET) {
						extra = parseTrailing(resource, RESOURCE_REPLICA);
						sendReplica(extra);
						status = true;
					}

				} else if (resource.startsWith(RESOURCE_MONITOR)) {
					log.debug("Processing resource '" + RESOURCE_MONITOR + "'");
					// there are various parts to monitoring
					if (httpVerb == GET) {
						extra = parseTrailing(resource, RESOURCE_MONITOR);

						// ping
						if (extra.toLowerCase().equals("ping")) {
							log.debug("processing ping request");

							Date result = DAPMNodeService.getInstance(request, db, logDb).ping();
							if (result != null) {
								log.debug("processing ping result: " + result.toString());

								response.setDateHeader("Date", result.getTime());
								response.setStatus(200);

								response.getWriter().println(result.toString());
							} else {
								log.debug("processing ping result: null");
								response.setStatus(400);

								response.getWriter() .println("No response from the underlying DAP server.");
							}

							status = true;
						}
					}
				} else if (resource.startsWith(RESOURCE_ERROR)) {
					log.debug("Processing resource '{}'", RESOURCE_ERROR);
					SynchronizationFailed sf = collectSynchronizationFailed();
					DAPMNodeService.getInstance(request, db, logDb).synchronizationFailed(sf);
					status = true;
				} else {
					throw new InvalidRequest("0000", "No resource matched for " + resource);
				}

				if (!status) {
					throw new ServiceFailure("0000", "Unknown error while processing resource: " + resource);
				}

			} catch (BaseException be) {
				// report Exceptions as clearly as possible
				OutputStream out = null;
				try {
					out = response.getOutputStream();
				} catch (IOException e) {
					log.error("Could not get output stream from response", e);
				}
				serializeException(be, out);
			} catch (Exception e) {
				// report Exceptions as clearly and generically as possible
				log.error(e.getClass() + ": " + e.getMessage(), e);
				OutputStream out = null;
				try {
					out = response.getOutputStream();
				} catch (IOException ioe) {
					log.error("Could not get output stream from response", ioe);
				}
				ServiceFailure se = new ServiceFailure("2162", e.getMessage());
				serializeException(se, out);
			}

		} catch (Exception e) {
			response.setStatus(400);
			printError("Incorrect resource!", response);
			log.error(e.getClass() + ": " + e.getMessage(), e);
		}
	}

	/**
	 * @brief Get a Session from the D1 CertificateManager
	 * 
	 * If there is no certificate, the Session member will be set to
	 * null. This method was made simply to reduce clutter in the
	 * handle() method.
	 * 
	 * @throws InvalidToken
	 */
	@SuppressWarnings("unused")
	private void getSession() throws InvalidToken {
		// initialize the session - two options
		// #1
		// load session from certificate in request
		session = CertificateManager.getInstance().getSession(request);

		// #2
		if (session == null) {
			// check for session-based certificate from the portal
			try {
				// FIXME: configurationFileName is null.
				String configurationFileName = servletContext.getInitParameter("oa4mp:client.config.file");
				String configurationFilePath = servletContext.getRealPath(configurationFileName);
				/*
				PortalCertificateManager portalManager = new PortalCertificateManager(configurationFilePath);
				log.debug("Initialized the PortalCertificateManager using config file: "+ configurationFilePath);
				X509Certificate certificate = portalManager.getCertificate(request);
				log.debug("Retrieved certificate: " + certificate);
				PrivateKey key = portalManager.getPrivateKey(request);
				log.debug("Retrieved key: " + key);
				if (certificate != null && key != null) {
					request.setAttribute("javax.servlet.request.X509Certificate", certificate);
					log.debug("Added certificate to the request: " + certificate.toString());
				}
				*/
				// reload session from certificate that we jsut set in request
				session = CertificateManager.getInstance().getSession(request);
			} catch (Throwable t) {
				// don't require configured OAuth4MyProxy
				log.error(t.getMessage(), t);
			}
		}
	}

	/**
	 * Get the Node information. This is where the getCapabilities() response is
	 * built.
	 * 
	 * @throws JiBXException
	 * @throws IOException
	 * @throws InvalidRequest
	 * @throws ServiceFailure
	 * @throws NotAuthorized
	 * @throws NotImplemented
	 */
	private void sendNodeResponse() throws JiBXException, IOException, NotImplemented, NotAuthorized, ServiceFailure, InvalidRequest {
		log.debug("in node...");

		Node n = DAPMNodeService.getInstance(request, db, logDb).getCapabilities();

		response.setContentType("text/xml");
		response.setStatus(200);
		TypeMarshaller.marshalTypeToOutputStream(n, response.getOutputStream());
	}

	private void sendSysmetaResponse(String extra) throws InvalidToken, NotAuthorized, NotImplemented, ServiceFailure, NotFound, JiBXException, IOException {
		log.debug("in sysmeta...");

		Identifier pid = new Identifier();
		pid.setValue(extra);
		
		SystemMetadata sm = DAPMNodeService.getInstance(request, db, logDb).getSystemMetadata(pid);

		response.setContentType("text/xml");
		response.setStatus(200);
		
		TypeMarshaller.marshalTypeToOutputStream(sm, response.getOutputStream());
	}
	
	/**
	 * Get a stream back the object. This gets the DAP URL from the database, dereferences it
	 * and uses IOUtils.copyLarge() to dump the result to the response's output stream.
	 * 
	 * @param extra The PID text
	 * 
	 * @throws InvalidToken
	 * @throws ServiceFailure
	 * @throws NotFound
	 * @throws InsufficientResources
	 * @throws NotAuthorized
	 * @throws NotImplemented
	 */
	private void sendObject(String extra) throws InvalidToken, ServiceFailure, NotFound, InsufficientResources, 
			NotAuthorized, NotImplemented {
		log.debug("in object (pid: {})...", extra);
		
		try {
			dereferenceDapURL(extra);
			
		} catch (SQLException e) {
			log.error("SQL Exception: {}", e.getMessage());
			throw new ServiceFailure("1030", e.getMessage());
		} catch (DAPDatabaseException e) {
			log.error("DAP Database Exception: {}", e.getMessage());
			throw new ServiceFailure("1030", e.getMessage());
		} catch (IOException e) {
			log.error("Failed to copy a response object to the sevlet's out stream: {}", e.getMessage());
			throw new ServiceFailure("1030", e.getMessage());
		}
	}

	/**
	 * Using the PID, lookup the DAP URL, dereference it and stream the result back
	 * to the client using the response object's output stream. This is used by both
	 * sendObject and sendReplica.
	 * 
	 * @param extra The D1 PID text.
	 * 
	 * @throws InvalidToken
	 * @throws NotAuthorized
	 * @throws NotImplemented
	 * @throws ServiceFailure
	 * @throws NotFound
	 * @throws InsufficientResources
	 * @throws SQLException
	 * @throws DAPDatabaseException
	 * @throws IOException
	 */
	private void dereferenceDapURL(String extra) throws InvalidToken,
			NotAuthorized, NotImplemented, ServiceFailure, NotFound,
			InsufficientResources, SQLException, DAPDatabaseException,
			IOException {
		Identifier pid = new Identifier();
		pid.setValue(extra);
		
		// get(pid) throws if 'pid' is null (i.e., it will not return a null InputStream)
		InputStream in = DAPMNodeService.getInstance(request, db, logDb).get(pid);

		/* Here's how they did it in the metacat server; as with describe, optimizing
		   access to the system metadata via the getSystemMetadata() call and then using
		   that here would probably boost performance. jhrg 6/10/14

        // set the headers for the content
        String mimeType = ObjectFormatInfo.instance().getMimeType(sm.getFormatId().getValue());
        if (mimeType == null) {
        	mimeType = "application/octet-stream";
        }
        String extension = ObjectFormatInfo.instance().getExtension(sm.getFormatId().getValue());
        String filename = id.getValue();
        if (extension != null) {
        	filename = id.getValue() + extension;
        }
        response.setContentType(mimeType);
        response.setHeader("Content-Disposition", "inline; filename=" + filename);
		
		*/
		
        String formatId = db.getFormatId(extra);
		String responseType = getResponseType(formatId);
		response.setContentType(responseType);

		response.setStatus(200);
		
		IOUtils.copyLarge(in, response.getOutputStream());
	}

	// ...could make this a map
	private String getResponseType(String formatId) {
		if (formatId.equals(DatasetsDatabase.SDO_FORMAT)) // netcdf
			return "application/octet-stream";
		else if (formatId.equals(DatasetsDatabase.SMO_FORMAT)) // iso19115
			return "text/xml";
		else if (formatId.equals(DatasetsDatabase.ORE_FORMAT)) // http ...
			return "text/xml";
		else
			return "text/plain";
	}

	/**
	 * Return an object in response to a /replica request. This differs from am /object 
	 * request only in how it is recorded in the log file and in the detail code for
	 * the ServiceFailure objects throw when various errors happen.
	 * 
	 * @param extra The PID text
	 * 
	 * @throws InvalidToken
	 * @throws ServiceFailure
	 * @throws NotFound
	 * @throws InsufficientResources
	 * @throws NotAuthorized
	 * @throws NotImplemented
	 */
	private void sendReplica(String extra) throws InvalidToken, ServiceFailure, NotFound, InsufficientResources, 
			NotAuthorized, NotImplemented {

		log.debug("in replica (pid: {})...", extra);
		
		if (!Settings.getConfiguration().getString("org.opendap.d1.nodeReplicate").equals("true"))
			throw new NotAuthorized("2182", "This host does not allow replication.");
		
		try {
			dereferenceDapURL(extra);
			
		} catch (SQLException e) {
			log.error("SQL Exception: {}", e.getMessage());
			throw new ServiceFailure("2181", e.getMessage());
		} catch (DAPDatabaseException e) {
			log.error("DAP Database Exception: {}", e.getMessage());
			throw new ServiceFailure("2181", e.getMessage());
		} catch (IOException e) {
			log.error("Failed to copy a response object to the sevlet's out stream: {}", e.getMessage());
			throw new ServiceFailure("2181", e.getMessage());
		}
	}

	/**
	 * Build the response to describe(). Unlike the other calls, describe() 
	 * is used with the http verb HEAD and puts metadata in the headers of the 
	 * response object. Otherwise, it is a call to retrieve system metadata.
	 * Also note that this never throws an exception. Instead, all exceptions
	 * are trapped and returned not as XML but in the response headers.
	 * 
	 * @param extra The PID text
	 * 
	 * @throws InvalidToken
	 * @throws NotAuthorized
	 * @throws NotImplemented
	 * @throws ServiceFailure
	 * @throws NotFound
	 * @throws JiBXException
	 * @throws IOException
	 */
	private void sendDescribeObject(String extra) {
		log.debug("in describe...");
	       
        response.setContentType("text/xml");

        Identifier pid = new Identifier();
        pid.setValue(extra);

        DescribeResponse dr = null;
        try {
        	dr = DAPMNodeService.getInstance(request, db, logDb).describe(pid);
        } catch (BaseException e) {
        	response.setStatus(e.getCode());
        	response.addHeader("DataONE-Exception-Name", e.getClass().getName());
            response.addHeader("DataONE-Exception-DetailCode", e.getDetail_code());
            response.addHeader("DataONE-Exception-Description", e.getDescription());
            response.addHeader("DataONE-Exception-PID", pid.getValue());
            return;
		}
        
        response.setStatus(200);
        
        //response.addHeader("pid", pid);
        response.addHeader("DataONE-Checksum", dr.getDataONE_Checksum().getAlgorithm() + "," + dr.getDataONE_Checksum().getValue());
        response.addHeader("Content-Length", dr.getContent_Length() + "");
        response.addHeader("Last-Modified", DateTimeMarshaller.serializeDateToUTC(dr.getLast_Modified()));
        response.addHeader("DataONE-ObjectFormat", dr.getDataONE_ObjectFormatIdentifier().getValue());
        response.addHeader("DataONE-SerialVersion", dr.getSerialVersion().toString());
	}

	/**
	 * Send the list of PIDs and their associated metadata in response to a GET /object
	 * request. This method extracts the arguments from the parameters parsed from the 
	 * URL's query string and passes them onto the 'NodeService' class which builds the
	 * actual DataONE response object. Once the response object is in hand, this method
	 * serializes it.
	 * 
	 * @note This servlet never holds replicas, so the 'replicas' parameter to this method
	 * is ignored. There's no error if it's given, because without replicas in the database
	 * the response would be the same regardless of the parameter's value.
	 *  
	 * @param params A Hashtable of parsed query string info where the QS keys are keys and
	 * the values are, well, values (arrays of strings).
	 * 
	 * @throws InvalidRequest
	 * @throws InvalidToken
	 * @throws NotAuthorized
	 * @throws NotImplemented
	 * @throws ServiceFailure
	 * @throws JiBXException
	 * @throws IOException
	 */
	private void sendListObjects(Hashtable<String, String[]> params) throws InvalidRequest, InvalidToken, 
			NotAuthorized, NotImplemented, ServiceFailure, JiBXException, IOException {
		// call listObjects with specified params
		Date fromDate = null;
		Date toDate = null;
		ObjectFormatIdentifier formatId = null;
		int start = 0;
		int count = DEFAULT_COUNT;

		try {
			// Hmmm Metacat used this class to parse the URL params, but it seems to assume that 
			// params should default to the local time. E.G. 2014-06-12T00:00:00 becomes
			// 2014-06-11T18:00:00 if we are at GMT-6. Our database stores time in GMT,
			// however, so I think we should perform no time zone conversion. If we need to
			// change this, make sure to also change the toDate stuff below. jhrg 6/11/14
			//
			// DateTimeMarshaller.deserializeDateToUTC(params.get("fromDate")[0]);
			
			if (params.get("fromDate") != null)
				fromDate = DAPD1DateParser.StringToDate(params.get("fromDate")[0]);
				
		} catch (Exception e) {
			log.warn("Could not parse toDate: " + params.get("fromDate")[0]);
			fromDate = null;
		}

		try {
			if (params.get("toDate") != null)
				toDate = DAPD1DateParser.StringToDate(params.get("toDate")[0]);
		} catch (Exception e) {
			log.warn("Could not parse toDate: " + params.get("toDate")[0]);
			toDate = null;
		}

		if (params.get("formatId") != null) {
			formatId = new ObjectFormatIdentifier();
			formatId.setValue(params.get("formatId")[0]);
		}

		if (params.get("start") != null)
			start = new Integer(params.get("start")[0]).intValue();

		if (params.get("count") != null)
			count = new Integer(params.get("count")[0]).intValue();

		log.debug("List Objects call, fromDate: " + fromDate + " toDate: "
				+ toDate + " formatId: " + formatId + " start: " + start + " count: " + count);

		// replicas == false (never return replicas). This is ignored but we include the 
		// parameter in this method because the implementation is of an interface and we
		// must provide a version of all of its methods. jhrg 6/11/14
		ObjectList ol = DAPMNodeService.getInstance(request, db, logDb).listObjects(fromDate, toDate, formatId, false,
				start, count);

		response.setStatus(200);
		response.setContentType("text/xml");
		// Serialize and write it to the output stream
		TypeMarshaller.marshalTypeToOutputStream(ol, response.getOutputStream());
	}

	private void sendLogEntries(Hashtable<String, String[]> params) 
			throws InvalidRequest, InvalidToken, NotAuthorized, NotImplemented, ServiceFailure, JiBXException, IOException {
		// call listObjects with specified params
		Date fromDate = null;
		Date toDate = null;
		Event event = null;
		String pidFilter = null;
		
		int start = 0;
		int count = DEFAULT_COUNT;

		try {
			if (params.get("fromDate") != null)
				fromDate = DAPD1DateParser.StringToDate(params.get("fromDate")[0]);
				
		} catch (Exception e) {
			log.warn("Could not parse toDate: " + params.get("fromDate")[0]);
			fromDate = null;
		}

		try {
			if (params.get("toDate") != null)
				toDate = DAPD1DateParser.StringToDate(params.get("toDate")[0]);
		} catch (Exception e) {
			log.warn("Could not parse toDate: " + params.get("toDate")[0]);
			toDate = null;
		}

		if (params.get("event") != null) {
			event = Event.convert(params.get("event")[0]);
		}

		if (params.get("pidFilter") != null) {
			pidFilter = params.get("pidFilter")[0];
		}
		
		if (params.get("start") != null)
			start = new Integer(params.get("start")[0]).intValue();

		if (params.get("count") != null)
			count = new Integer(params.get("count")[0]).intValue();

		log.debug("List log entries call, fromDate: " + fromDate + " toDate: " + toDate + " event: " + event
				+ " idFilter: " + pidFilter + " start: " + start + " count: " + count);

		Log D1Log = DAPMNodeService.getInstance(request, db, logDb).getLogRecords(fromDate, toDate, event, pidFilter,
				start, count);

		response.setStatus(200);
		response.setContentType("text/xml");
		// Serialize and write it to the output stream
		TypeMarshaller.marshalTypeToOutputStream(D1Log, response.getOutputStream());
	}

	private void sendChecksum(String extra, String algorithm) throws InvalidRequest, InvalidToken, NotAuthorized,
			NotImplemented, ServiceFailure, NotFound, JiBXException, IOException {
		log.debug("in checksum...");

		Identifier pid = new Identifier();
		pid.setValue(extra);
		
		Checksum c = DAPMNodeService.getInstance(request, db, logDb).getChecksum(pid, algorithm);

		response.setContentType("text/xml");
		response.setStatus(200);
		
		TypeMarshaller.marshalTypeToOutputStream(c, response.getOutputStream());
	}

    /**
     * Look for the org.opendap.d1.tempDir property and use its value or
     * the default value of "/tmp" to build a File object.
     * @return A File object for the temp directory
     */
    private static File getTempDirectory()
    {
    	String tempName = Settings.getConfiguration().getString("org.opendap.d1.tempDir");
    	if (tempName == null || tempName.isEmpty())
    		tempName = "/tmp";
    	log.debug("Temp directory name: {}", tempName);
        return  new File(tempName);
    }
    
	private SynchronizationFailed collectSynchronizationFailed() throws ServiceFailure, InvalidRequest, 
		ParserConfigurationException, SAXException, IOException {
		
		// Read the incoming data from its Mime Multipart encoding
		// handle MMP inputs
		File tmpDir = getTempDirectory();
		MultipartRequestResolver mrr = new MultipartRequestResolver(tmpDir.getAbsolutePath(), 1000000000, 0);
		MultipartRequest mr = null;
		try {
			mr = mrr.resolveMultipart(request);
		} catch (Exception e) {
			throw new ServiceFailure("2161", "Could not resolve multipart: " + e.getMessage());
		}

		Map<String, File> files = mr.getMultipartFiles();
		if (files == null || files.keySet() == null) {
			throw new InvalidRequest("2163", "must have multipart file with name 'message'");
		}
	
		// Map<String, List<String>> multipartparams = mr.getMultipartParameters();
	
		File sfFile = files.get("message");
		if (sfFile == null) {
			throw new InvalidRequest("2163", "Missing the required file-part 'message' from the multipart request.");
		}

		InputStream sf = new FileInputStream(sfFile);
	
		SynchronizationFailed syncFailed = (SynchronizationFailed) ExceptionHandler.deserializeXml(sf, "Error deserializing exception");

		return syncFailed;
	}
	
	/**
	 * Extract the path info following the string 'resource'.
	 * 
	 * @param resource
	 * @param token
	 * @return
	 */
	private String parseTrailing(String resource, String token) {
		// get the rest
		String extra = null;
		if (resource.indexOf(token) != -1) {
			// what comes after the token?
			extra = resource.substring(resource.indexOf(token) + token.length());
			// remove the slash
			if (extra.startsWith("/")) {
				extra = extra.substring(1);
			}
			// is there anything left?
			if (extra.length() == 0) {
				extra = null;
			}
		}
		return extra;
	}

	/**
	 * copies request parameters to a hash table which is given as argument to
	 * native metacat handler functions
	 */
	@SuppressWarnings({ "rawtypes" })
	private void initParams(Hashtable<String, String[]>params) {

		String name = null;
		String[] value = null;
		Enumeration paramlist = request.getParameterNames();
		while (paramlist.hasMoreElements()) {
			name = (String) paramlist.nextElement();
			value = request.getParameterValues(name);
			params.put(name, value);
		}
	}

	/**
	 * Prints xml response
	 * 
	 * @param message
	 *            Message to be displayed
	 * @param response
	 *            Servlet response that xml message will be printed
	 *
	 */
	private void printError(String message, HttpServletResponse response) {
		try {
			log.error("D1ResourceHandler: Printing error to servlet response: " + message);
			PrintWriter out = response.getWriter();
			response.setContentType("text/xml");
			out.println("<?xml version=\"1.0\"?>");
			out.println("<error>");
			out.println(message);
			out.println("</error>");
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * serialize a D1 exception using jibx
	 * 
	 * @param e
	 * @param out
	 */
	private void serializeException(BaseException e, OutputStream out) {
		response.setContentType("text/xml");
		response.setStatus(e.getCode());

		log.error("D1ResourceHandler: Serializing exception with code "
				+ e.getCode() + ": " + e.getMessage());
		e.printStackTrace();

		try {
			IOUtils.write(e.serialize(BaseException.FMT_XML), out);
		} catch (IOException e1) {
			log.error("Error writing exception to stream. "
					+ e1.getMessage());
		}
	}
}
