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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.log4j.Logger;
import org.dataone.client.auth.CertificateManager;
import org.dataone.configuration.Settings;
import org.dataone.portal.PortalCertificateManager;
import org.dataone.service.exceptions.BaseException;
import org.dataone.service.exceptions.InsufficientResources;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Checksum;
import org.dataone.service.types.v1.DescribeResponse;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.Node;
import org.dataone.service.types.v1.ObjectFormatIdentifier;
import org.dataone.service.types.v1.ObjectList;
import org.dataone.service.types.v1.Session;
import org.dataone.service.types.v1.SystemMetadata;
import org.dataone.service.util.DateTimeMarshaller;
import org.dataone.service.util.TypeMarshaller;
import org.jibx.runtime.JiBXException;
import org.opendap.d1.DatasetsDatabase.DAPDatabaseException;
import org.opendap.d1.DatasetsDatabase.DatasetsDatabase;

/**
 * @brief Handle GET, POST and HEAD requests for the DAP/D1 servlet.
 * 
 * MN REST service implementation handler
 * 
 * MNCore -- Partly 
 * ping() - GET /d1/mn/monitor/ping (done)
 * log() - GET /d1/mn/log 
 * getCapabilities() - GET /d1/mn/ and /d1/mn/node (done)
 * 
 * MNRead -- Partly 
 * get() - GET /d1/mn/object/PID (done)
 * getSystemMetadata() - GET /d1/mn/meta/PID (done)
 * getReplica() - GET /replica/PID (done)
 * describe() - HEAD /d1/mn/object/PID (done)
 * getChecksum() - GET /d1/mn/checksum/PID (done)
 * listObjects() - GET /d1/mn/object
 * synchronizationFailed() - POST /d1/mn/error
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
	
	// MN-specific API Resources
	private static final String RESOURCE_MONITOR = "monitor";
	private static final String RESOURCE_NODE = "node";
	private static final String RESOURCE_ERROR = "error";

	// The default number of responses for the listObjects() call
	private static int DEFAULT_COUNT = 1000;
	
	private static String OPENDAP_PROPERTIES = "opendap.properties";
	
	private ServletContext servletContext;
	private Logger logDAP;

	/// An open connection to the database that holds the dataset info
	protected DatasetsDatabase db;

	protected HttpServletRequest request;
	protected HttpServletResponse response;

	protected Hashtable<String, String[]> params;

	// D1 certificate-based authentication
	protected Session session;

	/**
	 * @brief Initializes new instance by setting servlet context,request and response.
	 * 
	 * This is called by DAPRestServlet.createHandler(). The resulting
	 * instance is used 'handle' the GET, POST or HEAD request.
	 */
	public DAPResourceHandler(ServletContext servletContext, HttpServletRequest request, HttpServletResponse response)
			throws DAPDatabaseException {
		
		logDAP = Logger.getLogger(DAPResourceHandler.class);
		
		this.servletContext = servletContext;
		this.request = request;
		this.response = response;
		
		try {
			Settings.augmentConfiguration(OPENDAP_PROPERTIES);
		}
		catch (ConfigurationException ce) {
			logDAP.error("Failed to read the config file: " + OPENDAP_PROPERTIES);
		}

		String dbName = Settings.getConfiguration().getString("org.opendap.d1.DatabaseName");
		// dbName = servletContext.getRealPath(dbName);
		logDAP.debug("in object (dbName: " + dbName + ")...");

		try {
			db = new DatasetsDatabase(dbName);
			if (!db.isValid())
				throw new DAPDatabaseException("The database is not valid (" + dbName + ").");
		} catch (SQLException e) {
			throw new DAPDatabaseException("The database is not valid (" + dbName + "): " + e.getMessage());
		} catch (ClassNotFoundException e) {
			throw new DAPDatabaseException("The database is not valid (" + dbName + "): " + e.getMessage());
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

			// initialize the parameters
			params = new Hashtable<String, String[]>();
			initParams();

			try {
				// get the resource
				String resource = request.getPathInfo();

				logDAP.debug("handling verb " + httpVerb
						+ " request with resource '" + resource + "'");

				// In the web.xml for the DAPRestServlet, I set the url pattern
				// like this: <url-pattern>/d1/mn/*</url-pattern> which means
				// that
				// the leading '/d1/mn/' is removed by the servlet container.
				// jhrg 5/20/14
				resource = resource.substring(resource.indexOf("/") + 1);

				logDAP.debug("processed resource: '" + resource + "'");

				// default to node info
				if (resource == null || resource.equals("")) {
					resource = RESOURCE_NODE;
				}

				// get the rest of the path info
				String extra = null;
				boolean status = false;

				if (resource.startsWith(RESOURCE_NODE)) {
					logDAP.debug("Using resource '" + RESOURCE_NODE + "'");
					// node (aka getCapabilities) response. The method uses
					// the output stream to serialize the result and throws an
					// exception if there's a problem.
					sendNodeResponse();
					status = true;
				} else if (resource.startsWith(RESOURCE_META)) {
					logDAP.debug("Using resource '" + RESOURCE_META + "'");
					// get
					if (httpVerb == GET) {
						// after the command
						extra = parseTrailing(resource, RESOURCE_META);
						sendSysmetaResponse(extra);
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_OBJECTS)) {
					// This is the get() call which returns SDOs and SMOs
					// or the describe() call for the same depending on the
					// HTTP verb (GET or HEAD)
					logDAP.debug("Using resource '" + RESOURCE_OBJECTS + "'");
					// after the command
					extra = parseTrailing(resource, RESOURCE_OBJECTS);
					logDAP.debug("objectId: " + extra);
					logDAP.debug("verb:" + httpVerb);

					if (httpVerb == GET) {
						if (extra == null || extra.isEmpty())
							sendListObjects(params);
						else
							sendObject(extra);
						status = true;
					} else if (httpVerb == HEAD) {
						sendDescribeObject(extra);
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_LOG)) {
					logDAP.debug("Using resource '" + RESOURCE_LOG + "'");
					// handle log events
					if (httpVerb == GET) {
						// FIXME getLog();
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_CHECKSUM)) {
					logDAP.debug("Using resource '" + RESOURCE_CHECKSUM + "'");
					// handle checksum requests
					if (httpVerb == GET) {
						// after the command
						extra = parseTrailing(resource, RESOURCE_CHECKSUM);
						String algorithm = "SHA-1";
						sendChecksum(extra, algorithm);
						status = true;
					}
				} else if (resource.startsWith(RESOURCE_REPLICA)) {
					logDAP.debug("Using resource '" + RESOURCE_REPLICA + "'");
					// handle replica requests
					if (httpVerb == GET) {
						// after the command
						extra = parseTrailing(resource, RESOURCE_REPLICA);
						sendReplica(extra);
						status = true;
					}

				} else if (resource.startsWith(RESOURCE_MONITOR)) {
					logDAP.debug("Processing resource '" + RESOURCE_MONITOR + "'");
					// there are various parts to monitoring
					if (httpVerb == GET) {
						// after the command
						extra = parseTrailing(resource, RESOURCE_MONITOR);

						// ping
						if (extra.toLowerCase().equals("ping")) {
							logDAP.debug("processing ping request");

							Date result = DAPMNodeService.getInstance(request, db).ping();
							if (result != null) {
								logDAP.debug("processing ping result: "
										+ result.toString());

								response.setDateHeader("Date", result.getTime());
								response.setStatus(200);

								response.getWriter().println(result.toString());
							} else {
								logDAP.debug("processing ping result: null");
								response.setStatus(400);

								response.getWriter() .println("No response from the underlying DAP server.");
							}

							status = true;
						}
					}
				} else if (resource.startsWith(RESOURCE_ERROR)) {
					// TODO Handle the POST /error thing
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
					logDAP.error("Could not get output stream from response", e);
				}
				serializeException(be, out);
			} catch (Exception e) {
				// report Exceptions as clearly and generically as possible
				logDAP.error(e.getClass() + ": " + e.getMessage(), e);
				OutputStream out = null;
				try {
					out = response.getOutputStream();
				} catch (IOException ioe) {
					logDAP.error("Could not get output stream from response", ioe);
				}
				ServiceFailure se = new ServiceFailure("2162", e.getMessage());
				serializeException(se, out);
			}

		} catch (Exception e) {
			response.setStatus(400);
			printError("Incorrect resource!", response);
			logDAP.error(e.getClass() + ": " + e.getMessage(), e);
		}
	}

	/**
	 * @brief Get a Session from the D1 CertificateManager
	 * 
	 * If there is no certificate, the Session member will be set to
	 * null. This method was made simply to reduce clutter in the
	 * handle() method.
	 * 
	 * FIXME configurationFileName is null so this code fails. 5/20/14
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
				String configurationFileName = servletContext
						.getInitParameter("oa4mp:client.config.file");
				String configurationFilePath = servletContext
						.getRealPath(configurationFileName);
				PortalCertificateManager portalManager = new PortalCertificateManager(
						configurationFilePath);
				logDAP.debug("Initialized the PortalCertificateManager using config file: "
						+ configurationFilePath);
				X509Certificate certificate = portalManager
						.getCertificate(request);
				logDAP.debug("Retrieved certificate: " + certificate);
				PrivateKey key = portalManager.getPrivateKey(request);
				logDAP.debug("Retrieved key: " + key);
				if (certificate != null && key != null) {
					request.setAttribute(
							"javax.servlet.request.X509Certificate",
							certificate);
					logDAP.debug("Added certificate to the request: "
							+ certificate.toString());
				}

				// reload session from certificate that we jsut set in request
				session = CertificateManager.getInstance().getSession(request);
			} catch (Throwable t) {
				// don't require configured OAuth4MyProxy
				logDAP.error(t.getMessage(), t);
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
	private void sendNodeResponse() throws JiBXException, IOException,
			NotImplemented, NotAuthorized, ServiceFailure, InvalidRequest {
		logDAP.debug("in node...");

		Node n = DAPMNodeService.getInstance(request, db).getCapabilities();

		response.setContentType("text/xml");
		response.setStatus(200);
		TypeMarshaller.marshalTypeToOutputStream(n, response.getOutputStream());
	}

	private void sendSysmetaResponse(String extra) throws InvalidToken, NotAuthorized, 
			NotImplemented, ServiceFailure, NotFound, JiBXException, IOException {
		logDAP.debug("in sysmeta...");

		Identifier pid = new Identifier();
		pid.setValue(extra);
		
		SystemMetadata sm = DAPMNodeService.getInstance(request, db).getSystemMetadata(pid);

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
		
		logDAP.debug("in object (pid: " + extra + ")...");
		try {
			dereferenceDapURL(extra);
			
		} catch (SQLException e) {
			logDAP.error("SQL Exception: " + e.getMessage());
			throw new ServiceFailure("1030", e.getMessage());
		} catch (DAPDatabaseException e) {
			logDAP.error("DAP Database Exception: " + e.getMessage());
			throw new ServiceFailure("1030", e.getMessage());
		} catch (IOException e) {
			logDAP.error("Failed to copy a response object to the sevlet's out stream: " + e.getMessage());
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
		
		// get(pid) throws if 'in' is null (i.e., it will not return a null InputStream)
		InputStream in = DAPMNodeService.getInstance(request, db).get(pid);

		/* Here's how they did it in the metacat server; as with describe, optimizing
		   access to the system metadata via the getSystemMetadata() call adn then using
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

		logDAP.debug("in replica (pid: " + extra + ")...");
		
		if (!Settings.getConfiguration().getString("org.opendap.d1.nodeReplicate").equals("true"))
			throw new NotAuthorized("2182", "This host does not allow replication.");
		
		try {
			dereferenceDapURL(extra);
			
		} catch (SQLException e) {
			logDAP.error("SQL Exception: " + e.getMessage());
			throw new ServiceFailure("2181", e.getMessage());
		} catch (DAPDatabaseException e) {
			logDAP.error("DAP Database Exception: " + e.getMessage());
			throw new ServiceFailure("2181", e.getMessage());
		} catch (IOException e) {
			logDAP.error("Failed to copy a response object to the sevlet's out stream: " + e.getMessage());
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
		logDAP.debug("in describe...");
	       
        response.setContentType("text/xml");

        Identifier pid = new Identifier();
        pid.setValue(extra);

        DescribeResponse dr = null;
        try {
        	dr = DAPMNodeService.getInstance(request, db).describe(pid);
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
			// params should be decided to the local time. E.G. 2014-06-12T00:00:00 becomes
			// 2014-06-11T18:00:00 here where we are at GMT-6. Our database stores time in GMT,
			// however, so I think we should perform no time zone conversion. If we need to
			// change this, make sure to also change the toDate stuff below. jhrg 6/11/14
			//
			// DateTimeMarshaller.deserializeDateToUTC(params.get("fromDate")[0]);
			
			if (params.get("fromDate") != null)
				fromDate = DateUtils.parseDate(params.get("fromDate")[0], new String[]{"yyyy-MM-dd'T'HH:mm:ss"});
				
		} catch (Exception e) {
			logDAP.warn("Could not parse toDate: " + params.get("fromDate")[0]);
			fromDate = null;
		}

		try {
			if (params.get("toDate") != null)
				toDate = DateUtils.parseDate(params.get("toDate")[0], new String[]{"yyyy-MM-dd'T'HH:mm:ss"});
		} catch (Exception e) {
			logDAP.warn("Could not parse toDate: " + params.get("toDate")[0]);
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

		// make the crud call
		logDAP.debug("List Objects call, fromDate: " + fromDate + " toDate: "
				+ toDate + " formatId: " + formatId + " start: " + start + " count: " + count);

		// replicas == false (never return replicas). This is ignored but we include the 
		// parameter in this method because the implementation is of an interface and we
		// must provide a version of all of its methods. jhrg 6/11/14
		ObjectList ol = DAPMNodeService.getInstance(request, db).listObjects(fromDate, toDate, formatId, false,
				start, count);

		response.setStatus(200);
		response.setContentType("text/xml");
		// Serialize and write it to the output stream
		TypeMarshaller.marshalTypeToOutputStream(ol, response.getOutputStream());
	}

	private void sendChecksum(String extra, String algorithm) throws InvalidRequest, InvalidToken, NotAuthorized,
			NotImplemented, ServiceFailure, NotFound, JiBXException, IOException {
		logDAP.debug("in checksum...");

		Identifier pid = new Identifier();
		pid.setValue(extra);
		
		Checksum c = DAPMNodeService.getInstance(request, db).getChecksum(pid, algorithm);

		response.setContentType("text/xml");
		response.setStatus(200);
		
		TypeMarshaller.marshalTypeToOutputStream(c, response.getOutputStream());
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
	private void initParams() {

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
			logDAP.error("D1ResourceHandler: Printing error to servlet response: " + message);
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

		logDAP.error("D1ResourceHandler: Serializing exception with code "
				+ e.getCode() + ": " + e.getMessage());
		e.printStackTrace();

		try {
			IOUtils.write(e.serialize(BaseException.FMT_XML), out);
		} catch (IOException e1) {
			logDAP.error("Error writing exception to stream. "
					+ e1.getMessage());
		}
	}
}
