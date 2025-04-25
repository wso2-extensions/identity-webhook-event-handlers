package org.wso2.identity.webhook.common.event.handler.util;

import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;

import static org.testng.Assert.assertEquals;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;

public class EventPayloadUtilsTest {

    @BeforeClass
    public void setup() {

        MockitoAnnotations.openMocks(this);
    }

    @AfterClass
    public void tearDown() {
        // Clean up resources if needed
        closeMockedServiceURLBuilder();
    }

    @Test
    public void constructFullURLWithEndpointReturnsCorrectURL() {

        String endpoint = "/api/events";
        String expectedURL = "https://localhost:9443/api/events";

        TestUtils.mockServiceURLBuilder();
        String fullURL = EventPayloadUtils.constructFullURLWithEndpoint(endpoint);
        assertEquals(fullURL, expectedURL, "Full URL should be correctly constructed.");
        closeMockedServiceURLBuilder();
    }

    @Test
    public void constructFullURLWithEndpointHandlesEmptyEndpoint() {

        String endpoint = "";
        String expectedURL = "https://localhost:9443";

        TestUtils.mockServiceURLBuilder();
        String fullURL = EventPayloadUtils.constructFullURLWithEndpoint(endpoint);
        assertEquals(fullURL, expectedURL, "Full URL should handle empty endpoint correctly.");
        closeMockedServiceURLBuilder();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void constructFullURLWithEndpointThrowsExceptionForNullEndpoint() {

        TestUtils.mockServiceURLBuilder();
        EventPayloadUtils.constructFullURLWithEndpoint(null);
        closeMockedServiceURLBuilder();
    }

}
