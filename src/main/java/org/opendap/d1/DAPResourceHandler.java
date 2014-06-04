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

//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
//import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
//import java.util.Iterator;
//import java.util.List;
//import java.util.Map;
//import java.util.Timer;

import javax.servlet.ServletContext;
//import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
//import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.configuration.ConfigurationException;
//import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.dataone.client.auth.CertificateManager;
import org.dataone.configuration.Settings;
//import org.dataone.mimemultipart.MultipartRequest;
//import org.dataone.mimemultipart.MultipartRequestResolver;
import org.dataone.portal.PortalCertificateManager;
import org.dataone.service.exceptions.BaseException;
import org.dataone.service.exceptions.InsufficientResources;
import org.dataone.service.exceptions.InvalidRequest;
import org.dataone.service.exceptions.InvalidToken;
import org.dataone.service.exceptions.NotAuthorized;
import org.dataone.service.exceptions.NotFound;
import org.dataone.service.exceptions.NotImplemented;
import org.dataone.service.exceptions.ServiceFailure;
import org.dataone.service.types.v1.Identifier;
import org.dataone.service.types.v1.SystemMetadata;
//import org.dataone.service.types.v1.AccessPolicy;
import org.dataone.service.types.v1.Node;
//import org.dataone.service.types.v1.Group;
//import org.dataone.service.types.v1.Person;
//import org.dataone.service.types.v1.Replica;
//import org.dataone.service.types.v1.ReplicationPolicy;
import org.dataone.service.types.v1.Session;
//import org.dataone.service.types.v1.Subject;
//import org.dataone.service.types.v1.SubjectInfo;
//import org.dataone.service.types.v1.SystemMetadata;
import org.dataone.service.util.Constants;
//import org.dataone.service.util.ExceptionHandler;
import org.dataone.service.util.TypeMarshaller;

import org.jibx.runtime.JiBXException;

import org.opendap.d1.DatasetsDatabase.DAPDatabaseException;
//import org.xml.sax.SAXException;
import org.opendap.d1.DatasetsDatabase.DatasetsDatabase;

/**
 * @brief Handle GET, POST and HEAD requests for the DAP/D1 servlet.
 * 
 * MN REST service implementation handler
 * 
 * MNCore -- Partly 
 * ping() - GET /d1/mn/monitor/ping (done)
 * log() - GET /d1/mn/log 
 * **getObjectStatistics() - GET /d1/mn/monitor/object 
 * **getOperationsStatistics - GET /d1/mn/monitor/event 
 * **getStatus - GET /d1/mn/monitor/status
 * getCapabilities() - GET /d1/mn/ and /d1/mn/node (done)
 * 
 * MNRead -- Not yet 
 * get() - GET /d1/mn/object/PID 
 * getSystemMetadata() - GET /d1/mn/meta/PID 
 * describe() - HEAD /d1/mn/object/PID 
 * getChecksum() - GET /d1/mn/checksum/PID 
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
	private static final String RESOURCE_META = "meta";
	private static final String RESOURCE_LOG = "log";

	// MN-specific API Resources
	private static final String RESOURCE_MONITOR = "monitor";
	private static final String RESOURCE_NODE = "node";

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
	 * This function is called from REST API servlet and handles each request
	 * 
	 * @param httpVerb (GET, POST)
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

				logDAP.debug("handling verb " + httpVerb + " request with resource '" + resource + "'");

				// In the web.xml for the DAPRestServlet, I set the url pattern
				// like this: <url-pattern>/d1/mn/*</url-pattern> which means that
				// the leading '/d1/mn/' is removed by the servlet container. jhrg 5/20/14
				resource = resource.substring(resource.indexOf("/") + 1);

				logDAP.debug("processed resource: '" + resource + "'");

				// default to node info
				if (resource.equals("")) {
					resource = RESOURCE_NODE;
				}

				// get the rest of the path info
				String extra = null;
				boolean status = false;
				if (resource != null) {
					if (resource.startsWith(RESOURCE_NODE)) {
						logDAP.debug("Using resource 'node'");
						// node (aka getCapabilities) response. The method uses
						// the output stream to serialize the result and throws an
						// exception if there's a problem.
						sendNodeResponse();
						status = true;
					} else if (resource.startsWith(RESOURCE_META)) {
						logDAP.debug("Using resource 'meta'");
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
						logDAP.debug("Using resource 'object'");
						// after the command
						extra = parseTrailing(resource, RESOURCE_OBJECTS);
						logDAP.debug("objectId: " + extra);
						logDAP.debug("verb:" + httpVerb);

						if (httpVerb == GET) {
							getObject(extra);
							status = true;
						} else if (httpVerb == HEAD) {
							// FIXME describeObject(extra);
							status = true;
						}
					} else if (resource.startsWith(RESOURCE_LOG)) {
						logDAP.debug("Using resource 'log'");
						// handle log events
						if (httpVerb == GET) {
							// FIXME getLog();
							status = true;
						}
					} else if (resource.startsWith(Constants.RESOURCE_CHECKSUM)) {
						logDAP.debug("Using resource 'checksum'");
						// handle checksum requests
						if (httpVerb == GET) {
							// after the command
							extra = parseTrailing(resource, Constants.RESOURCE_CHECKSUM);
							// FIXME checksum(extra);
							status = true;
						}
					} else if (resource.startsWith(RESOURCE_MONITOR)) {
						logDAP.debug("processing monitor request");
						// there are various parts to monitoring
						if (httpVerb == GET) {
							// after the command
							extra = parseTrailing(resource, RESOURCE_MONITOR);

							// ping
							if (extra.toLowerCase().equals("ping")) {
								logDAP.debug("processing ping request");

								Date result = DAPMNodeService.getInstance(request, db).ping();
								if (result != null) {
									logDAP.debug("processing ping result: " + result.toString());

									response.setDateHeader("Date", result.getTime());
									response.setStatus(200);

									response.getWriter().println(result.toString());
								} 
								else {
									logDAP.debug("processing ping result: null");
									response.setStatus(400);

									response.getWriter().println("No response from the underlying DAP server.");
								}

								status = true;

							} 
							else {
								// health monitoring calls
								// FIXME status = monitor(extra);
								status = true;
							}
						}
					} else {
						throw new InvalidRequest("0000", "No resource matched for " + resource);
					}

					if (!status) {
						throw new ServiceFailure("2010", "Unknown error, status = " + status);
					}
				} // if (resource != null)
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
				ServiceFailure se = new ServiceFailure("0000", e.getMessage());
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
		// initialize the session - three options
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

		// #3
		// last resort, check for Metacat sessionid
		// This option has been removed since the DAP/D1 servlet does not use
		// metacat
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
	
	private void getObject(String extra) throws InvalidToken, ServiceFailure, NotFound, InsufficientResources, 
			NotAuthorized, NotImplemented {
		
		logDAP.debug("in object (pid: " + extra + ")...");
		try {
			Identifier pid = new Identifier();
			pid.setValue(extra);
			
			// get(pid) throws if 'in' is null
			InputStream in = DAPMNodeService.getInstance(request, db).get(pid);

			String formatId = db.getFormatId(extra);
			String responseType = getResponseType(formatId);
			response.setContentType(responseType);

			response.setStatus(200);
			
			IOUtils.copyLarge(in, response.getOutputStream());
			
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

	private String parseTrailing(String resource, String token) {
		// get the rest
		String extra = null;
		if (resource.indexOf(token) != -1) {
			// what comes after the token?
			extra = resource
					.substring(resource.indexOf(token) + token.length());
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
		// TODO: Use content negotiation to determine which return format to use
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
