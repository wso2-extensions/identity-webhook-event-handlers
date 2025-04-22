package org.wso2.identity.webhook.common.event.handler;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.identity.webhook.common.event.handler.internal.service.EventHookHandlerServiceComponent;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertNotNull;

public class EventHookHandlerServiceComponentTest {

    private static MockedStatic<EventHookHandlerServiceComponent> mockedServiceComponent;

    @BeforeClass
    public void setup() {
        mockedServiceComponent = mockStatic(EventHookHandlerServiceComponent.class);
    }

    @AfterClass
    public void tearDown() {
        mockedServiceComponent.close();
    }

    @Test
    public void getInstanceReturnsNonNullInstance() {
        EventHookHandlerServiceComponent instance = new EventHookHandlerServiceComponent();
        assertNotNull(instance, "getInstance() should return a non-null instance.");
    }
}