package org.wso2.identity.webhook.common.event.handler.component;

import org.testng.annotations.Test;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;

import java.util.ArrayList;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;

public class EventHookHandlerDataHolderTest {

    // Test methods for EventHookHandlerDataHolder class can be added here.
    // For example, you can test the singleton instance, initialization, etc.

    @Test
    public void testSingletonInstance() {
        EventHookHandlerDataHolder instance1 = EventHookHandlerDataHolder.getInstance();
        EventHookHandlerDataHolder instance2 = EventHookHandlerDataHolder.getInstance();
        assertNotNull(instance1, "Instance should not be null");
        assertSame(instance1, instance2, "Both instances should be the same (singleton)");
    }


    @Test
    public void testSetLoginEventPayloadBuilder() {
        EventHookHandlerDataHolder instance = EventHookHandlerDataHolder.getInstance();
        LoginEventPayloadBuilder mockedLoginEventPayloadBuilder = mock(LoginEventPayloadBuilder.class);
        ArrayList<LoginEventPayloadBuilder> loginEventPayloadBuilders = new ArrayList<>();
        loginEventPayloadBuilders.add(mockedLoginEventPayloadBuilder);
        instance.setLoginEventPayloadBuilders(loginEventPayloadBuilders);
        assertNotNull(instance.getLoginEventPayloadBuilders(), "LoginEventPayloadBuilders should not be null");
    }


}
