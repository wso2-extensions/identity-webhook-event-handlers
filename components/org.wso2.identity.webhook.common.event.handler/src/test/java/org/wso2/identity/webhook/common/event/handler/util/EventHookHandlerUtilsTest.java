package org.wso2.identity.webhook.common.event.handler.util;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.*;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.webhook.common.event.handler.api.util.EventHookHandlerUtils;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;

public class EventHookHandlerUtilsTest {

    @InjectMocks
    private EventHookHandlerUtils eventHookHandlerUtils;

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
        String fullURL = eventHookHandlerUtils.constructFullURLWithEndpoint(endpoint);
        assertEquals(fullURL, expectedURL, "Full URL should be correctly constructed.");
        closeMockedServiceURLBuilder();
    }

    @Test
    public void constructFullURLWithEndpointHandlesEmptyEndpoint() {
        String endpoint = "";
        String expectedURL = "https://localhost:9443";

        TestUtils.mockServiceURLBuilder();
        String fullURL = eventHookHandlerUtils.constructFullURLWithEndpoint(endpoint);
        assertEquals(fullURL, expectedURL, "Full URL should handle empty endpoint correctly.");
        closeMockedServiceURLBuilder();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void constructFullURLWithEndpointThrowsExceptionForNullEndpoint() {
        TestUtils.mockServiceURLBuilder();
        eventHookHandlerUtils.constructFullURLWithEndpoint(null);
        closeMockedServiceURLBuilder();
    }

    @Test
    public void getInstanceEnsuresThreadSafety() throws InterruptedException {
        final EventHookHandlerUtils[] instances = new EventHookHandlerUtils[2];

        Thread thread1 = new Thread(() -> instances[0] = EventHookHandlerUtils.getInstance());
        Thread thread2 = new Thread(() -> instances[1] = EventHookHandlerUtils.getInstance());

        thread1.start();
        thread2.start();
        thread1.join();
        thread2.join();

        assertNotNull(instances[0], "Instance from thread1 should not be null.");
        assertNotNull(instances[1], "Instance from thread2 should not be null.");
        assertEquals(instances[0], instances[1], "Both threads should return the same instance.");
    }

}
