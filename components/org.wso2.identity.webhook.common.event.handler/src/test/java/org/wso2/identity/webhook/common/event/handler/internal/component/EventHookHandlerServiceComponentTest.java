/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.internal.component;

import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;

import static org.mockito.Mockito.mock;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class for EventHookHandlerServiceComponent.
 */
public class EventHookHandlerServiceComponentTest {

    @InjectMocks
    private EventHookHandlerServiceComponent eventHookHandlerServiceComponent;

    @BeforeClass
    public void setup() {

        MockitoAnnotations.openMocks(this);
    }

    @AfterClass
    public void tearDown() {

    }

    @Test
    public void getInstanceReturnsNonNullInstance() {

        EventHookHandlerServiceComponent instance = new EventHookHandlerServiceComponent();
        assertNotNull(instance, "getInstance() should return a non-null instance.");
    }

    @Test
    public void testAddLoginEventPayloadBuilder() {

        EventHookHandlerDataHolder instance = EventHookHandlerDataHolder.getInstance();
        LoginEventPayloadBuilder mockedLoginEventPayloadBuilder = mock(LoginEventPayloadBuilder.class);
        eventHookHandlerServiceComponent.addLoginEventPayloadBuilder(mockedLoginEventPayloadBuilder);

        assertNotNull(instance.getLoginEventPayloadBuilders(),
                "LoginEventPayloadBuilders should not be null");
        assertEquals(instance.getLoginEventPayloadBuilders().size(), 1,
                "LoginEventPayloadBuilders should contain one element");
        assertTrue(instance.getLoginEventPayloadBuilders().contains(mockedLoginEventPayloadBuilder),
                "LoginEventPayloadBuilders should contain the added element");
    }

    @Test
    public void testAddSessionEventPayloadBuilder() {

        EventHookHandlerDataHolder instance = EventHookHandlerDataHolder.getInstance();
        SessionEventPayloadBuilder mockedSessionEventPayloadBuilder = mock(SessionEventPayloadBuilder.class);
        eventHookHandlerServiceComponent.addSessionEventPayloadBuilder(mockedSessionEventPayloadBuilder);

        assertNotNull(instance.getSessionEventPayloadBuilders(),
                "SessionEventPayloadBuilders should not be null");
        assertEquals(instance.getSessionEventPayloadBuilders().size(), 1,
                "SessionEventPayloadBuilders should contain one element");
        assertTrue(instance.getSessionEventPayloadBuilders().contains(mockedSessionEventPayloadBuilder),
                "SessionEventPayloadBuilders should contain the added element");
    }

    @Test
    public void testAddCredentialEventPayloadBuilder() {

        EventHookHandlerDataHolder instance = EventHookHandlerDataHolder.getInstance();
        CredentialEventPayloadBuilder mockedCredentialEventPayloadBuilder = mock(CredentialEventPayloadBuilder.class);
        eventHookHandlerServiceComponent.addCredentialEventPayloadBuilder(mockedCredentialEventPayloadBuilder);

        assertNotNull(instance.getCredentialEventPayloadBuilders(),
                "CredentialEventPayloadBuilders should not be null");
        assertEquals(instance.getCredentialEventPayloadBuilders().size(), 1,
                "CredentialEventPayloadBuilders should contain one element");
        assertTrue(instance.getCredentialEventPayloadBuilders().contains(mockedCredentialEventPayloadBuilder),
                "CredentialEventPayloadBuilders should contain the added element");
    }
}
