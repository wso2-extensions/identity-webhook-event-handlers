/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.webhook.common.event.handler.api.util;

import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.slf4j.MDC;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit test class for EventPayloadUtils.
 */
public class EventPayloadUtilsTest {

    @BeforeClass
    public void setup() {

        MockitoAnnotations.openMocks(this);
    }

    @AfterMethod
    public void tearDown() {
        // Clean up resources if needed
        closeMockedServiceURLBuilder();
    }

    @Test
    public void constructFullURLWithEndpointReturnsCorrectURL() {

        String endpoint = "/api/events";
        String expectedURL = "https://localhost:9443/api/events";

        mockServiceURLBuilder();
        String fullURL = EventPayloadUtils.constructFullURLWithEndpoint(endpoint);
        assertEquals(fullURL, expectedURL, "Full URL should be correctly constructed.");
        closeMockedServiceURLBuilder();
    }

    @Test
    public void constructFullURLWithEndpointHandlesEmptyEndpoint() {

        String endpoint = "";
        String expectedURL = "https://localhost:9443";

        mockServiceURLBuilder();
        String fullURL = EventPayloadUtils.constructFullURLWithEndpoint(endpoint);
        assertEquals(fullURL, expectedURL, "Full URL should handle empty endpoint correctly.");
        closeMockedServiceURLBuilder();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void constructFullURLWithEndpointThrowsExceptionForNullEndpoint() {

        mockServiceURLBuilder();
        EventPayloadUtils.constructFullURLWithEndpoint(null);
        closeMockedServiceURLBuilder();
    }

    /**
     * Test for correlation ID generation.
     */
    @Test
    public void testGetCorrelationID() {

        String correlationID = EventPayloadUtils.getCorrelationID();
        assertNotNull(correlationID, "Correlation ID should not be null");
        // Test if correlation ID is a valid UUID format
        assertTrue(correlationID.matches(
                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"));
    }

    @Test
    public void testConstructBaseURL() {

        mockServiceURLBuilder();
        String baseURL = EventPayloadUtils.constructBaseURL();
        assertEquals(baseURL, "https://localhost:9443", "Base URL should be correctly constructed.");
        closeMockedServiceURLBuilder();
    }

    @Test
    public void testConstructBaseURLSuccess() {

        mockServiceURLBuilder();
        String baseURL = EventPayloadUtils.constructBaseURL();
        assertNotNull(baseURL, "Base URL should not be null");
        closeMockedServiceURLBuilder();
    }

    @Test
    public void testGetCorrelationIDWithExistingCorrelationID() {

        String expectedCorrelationID = "test-correlation-id";
        try (MockedStatic<MDC> mockedMDC = mockStatic(MDC.class)) {
            mockedMDC.when(() -> MDC.get("Correlation-ID")).thenReturn(expectedCorrelationID);

            String correlationID = EventPayloadUtils.getCorrelationID();

            assertNotNull(correlationID, "Correlation ID should not be null");
            assertEquals(correlationID, expectedCorrelationID, "Correlation ID should match the expected value");

            mockedMDC.verify(() -> MDC.put("Correlation-ID", expectedCorrelationID), times(0));
        }
    }

    @Test
    public void testGetCorrelationIDWithoutExistingCorrelationID() {

        MDC.clear();
        String correlationID = EventPayloadUtils.getCorrelationID();
        assertNotNull(correlationID, "A new correlation ID should be generated");
    }

    @Test
    public void testGetCorrelationIDWhenMDCNotSet() {

        MDC.clear();
        String correlationID = EventPayloadUtils.getCorrelationID();
        assertNotNull(correlationID);
        assertTrue(correlationID.matches(
                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"));
    }
}
