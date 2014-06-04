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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opendap.d1.DatasetsDatabase.DAPDatabaseException;


/**
 * DAP implementation of Earthgrid (Ecogrid) REST API as a servlet. For each request the
 * REST servlet initializes a DAPResourceHandler object that then handles the request
 * and writes appropriate response. Because DAP servers do not support writes, this 
 * servlet does not support the PUT or DELETE verbs of HTTP and will return METHOD_NOT_ALLOWED
 * or BAD_REQUEST. This code processes GET, POST and HEAD HTTP verbs by making an instance
 * of DAPResourceHandler and passing a string to that class' handle() method. That class,
 * in turn does some servlet stuff and passes of the actual D1/DAP specific work to DAPMNodeService. 
 * 
 * @note This is based on code originally from the Metacat software written by Serhan AKIN,
 * Copyright GPL Regents of the University of California and NCEAS.
 * 
 * @see DAPResourceHandler, DAPMNodeService
 * 
 * @author James Gallagher
 */
public class DAPRestServlet extends HttpServlet {

    /**
	 * Serialization ID. Providing this overrides the default which can be 
	 * brittle since minor changes in the class will cause a new ID to be 
	 * automatically generated. ID mismatches between deserialized instances
	 * and current runtime instances result in InvalidClassException.
	 */
	private static final long serialVersionUID = 1L;
	
	protected Logger logDAP;
    protected DAPResourceHandler resourceHandler;

    /**
     * Subclasses should override this method to provide the appropriate resourceHandler subclass
     * @param request
     * @param response
     * @return
     * @throws ServletException
     * @throws IOException
     */
    protected DAPResourceHandler createHandler(HttpServletRequest request, HttpServletResponse response) 
    		throws ServletException, IOException {
    	DAPResourceHandler handler = null;
		try {
			handler = new DAPResourceHandler(getServletContext(), request, response);
		} catch (DAPDatabaseException e) {
			logDAP.error("Database access failure: " + e.getMessage());
			throw new ServletException(e);
		}

		return handler;
	}

	/**
	 * Initialize servlet by setting logger.
	 * 
	 * The servlet uses the D1 Settings class for configuration values (which in
	 * turn uses Apache Commons Configuration). This amounts to reading the
	 * configuration parameters from 'opendap.properties' in src/java/resources.
	 */
    @Override
    public void init(ServletConfig config) throws ServletException {
        logDAP = Logger.getLogger(this.getClass());

        super.init(config);
    }

    /**
     * It seems reasonable that we might be able to support this since Hyrax 
     * does return it and our (maybe) cached responses will likely include it.
     * 
     * A placeholder for now.
     * 
     * For now, just pass the call to the parent class.
     */
    @Override
    protected long getLastModified(HttpServletRequest req) {
    	return super.getLastModified(req);
    }

    /** 
     * @brief Handle "GET" method requests from HTTP clients
     * 
     * This should handle the case where the client sent a HEAD request (look
     * for a NoBodyResponse as the class of the 'response' parameter).
     * 
     * This should set ContentLength using response.setContentLength().
     * If possible, set LMT using 
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        logDAP.debug("HTTP Verb: GET");
        
        resourceHandler = createHandler(request, response);
        resourceHandler.handle(DAPResourceHandler.GET);
    }

    /** 
     * @brief Handle "POST" method requests from HTTP clients 
     * 
     * This method does not have to check for a NoBodyResponse (HEAD requests
     * are always processed by doGet()).
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	super.doPost(request, response);
    	/*
    	System.out.println("HTTP Verb: POST");
        resourceHandler = createHandler(request, response);
        resourceHandler.handle(DAPResourceHandler.POST);
        */
    }

}
