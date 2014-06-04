package org.opendap.d1;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class DAPMNodeServiceTest extends TestCase {

	public DAPMNodeServiceTest() {
		// TODO Auto-generated constructor stub
	}

	public DAPMNodeServiceTest(String testName) {
		super(testName);
		// TODO Auto-generated constructor stub
	}

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( DAPMNodeServiceTest.class );
    }

    /**
     * Rigorous Test :-)
     */
    public void testPing()
    {
        assertTrue( true );
    }

}
