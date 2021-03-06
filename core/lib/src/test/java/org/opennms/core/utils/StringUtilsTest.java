/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2002-2014 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2014 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/

package org.opennms.core.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;

import org.junit.Test;

public class StringUtilsTest {
    
    private String[] m_expected = { "The", "quick", "fox" };

    @Test
    public void testSimpleCommandArray() {
        String arg = "The   quick fox";
        testCreateCmdArray(m_expected, arg);
    }
    
    @Test
    public void testQuotedCommandArray() {
        testCreateCmdArray(m_expected, "\"The\" \"quick\" \"fox\"");
    }

    /**
     * The behavior with \t \n and \r characters inside a quoted
     * segment is odd.
     */
    @Test
    public void testQuotesContainingWhitespace() {
        String arg = "The quick \"brown \t\n\r \" fox";
        String[] actual = StringUtils.createCommandArray(arg);
        assertArrayEquals(new String[]{ "The", "quick", "brown ", " ", "fox" }, actual);
    }

    @Test
    public void testCommandArrayWithSpecialChars() {
        String arg = "The quick fox !@#$%^&*()-+[]{}|;:<>?,./";
        String[] actual = StringUtils.createCommandArray(arg);
        assertArrayEquals(new String[]{
                "The", "quick", "fox", "!@#$%^&*()-+[]{}|;:<>?,./"
                }, actual);
    }

    // Check NMS-6331 for more details.
    @Test
    public void testRrdPathWithSpaces() {
        String arg = "/usr/bin/rrdtool graph - --start 1463938619 --end 1464025019 --title=\"fwdd Uptime\" DEF:time=\"snmp/fs/The OpenNMS Office/Main Router/juniper-fwdd-process.rrd\":junFwddUptime:AVERAGE";
        String[] actual = StringUtils.createCommandArray(arg);
        assertArrayEquals(new String[]{
                "/usr/bin/rrdtool", "graph", "-", "--start", "1463938619", "--end", "1464025019", "--title=fwdd Uptime", "DEF:time=snmp/fs/The OpenNMS Office/Main Router/juniper-fwdd-process.rrd:junFwddUptime:AVERAGE"
                }, actual);
    }

    @Test
    public void testWindowsPaths() {
    	if (File.separatorChar != '\\') return;
    	if (Boolean.getBoolean("java.awt.headless")) return;
    	
    	final String[] trueStrings = new String[] { "C:\\monkey", "C:/monkey", "C:/", "C:\\" };
    	final String[] falseStrings = new String[] { "C:", "foo/bar", "/tmp/blah", "", "/", "blah:baz" };
    	
    	for (final String trueString : trueStrings) {
    		assertTrue(trueString, StringUtils.isLocalWindowsPath(trueString));
    	}
    	for (final String falseString : falseStrings) {
    		assertFalse(falseString, StringUtils.isLocalWindowsPath(falseString));
    	}
    }
    
    @Test
    public void testIso8601OffsetString() {
        assertEquals("1970-01-01T00:00:00Z", StringUtils.iso8601OffsetString(new Date(0), ZoneId.of("Z"), null));
        assertEquals("1970-01-01T00:00:00.001Z", StringUtils.iso8601OffsetString(new Date(1), ZoneId.of("Z"), null));
    }
    
    @Test
    public void testIso8601LocalOffsetString() {
        assertEquals(StringUtils.iso8601OffsetString(new Date(0), ZoneId.systemDefault(), null), StringUtils.iso8601LocalOffsetString(new Date(0)));
    }

    private void testCreateCmdArray(String[] expected, String arg) {
        String[] actual = StringUtils.createCommandArray(arg);
        assertArrayEquals(expected, actual);
    }
    
    private void assertArrayEquals(String[] expected, String[] actual) {
        assertEquals(Arrays.asList(expected), Arrays.asList(actual));
    }
}
