package org.wso2.identity.webhook.common.event.handler.util;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.webhook.common.event.handler.api.util.EventHookHandlerUtils;

import static org.testng.Assert.assertEquals;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;

public class EventHookHandlerUtilsTest {


    @Mock
    private EventPublisherService mockedEventPublisherService;

    @InjectMocks
    private EventHookHandlerUtils eventHookHandlerUtils;

    @BeforeMethod
    public void setup() {

        MockitoAnnotations.openMocks(this);
    }


    @Test
    public void testConstructFullURLWithEndpoint() {

        TestUtils.mockServiceURLBuilder();
        EventHookHandlerUtils utils = EventHookHandlerUtils.getInstance();
        String endpoint = "/api/test";
        String result = utils.constructFullURLWithEndpoint(endpoint);
        assertEquals(result, "https://localhost:9443" + endpoint);
        closeMockedServiceURLBuilder();
    }
}
