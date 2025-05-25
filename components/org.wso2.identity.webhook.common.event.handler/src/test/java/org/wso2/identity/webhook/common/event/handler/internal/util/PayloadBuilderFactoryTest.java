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

package org.wso2.identity.webhook.common.event.handler.internal.util;

import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.VerificationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;

import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Test class for PayloadBuilderFactory.
 */
public class PayloadBuilderFactoryTest {

    private UserOperationEventPayloadBuilder mockUserOperationEventPayloadBuilder;
    private LoginEventPayloadBuilder mockWSO2LoginBuilder;
    private SessionEventPayloadBuilder mockCAEPSessionBuilder;
    private CredentialEventPayloadBuilder mockCAEPCredentialBuilder;
    private VerificationEventPayloadBuilder mockCAEPVerificationBuilder;
    private RegistrationEventPayloadBuilder mockRegistrationEventPayloadBuilder;

    @BeforeClass
    public void setup() {

        mockWSO2LoginBuilder = Mockito.mock(LoginEventPayloadBuilder.class);
        mockUserOperationEventPayloadBuilder = Mockito.mock(UserOperationEventPayloadBuilder.class);
        mockRegistrationEventPayloadBuilder = Mockito.mock(RegistrationEventPayloadBuilder.class);
        mockCAEPSessionBuilder = Mockito.mock(SessionEventPayloadBuilder.class);
        mockCAEPCredentialBuilder = Mockito.mock(CredentialEventPayloadBuilder.class);
        mockCAEPVerificationBuilder = Mockito.mock(VerificationEventPayloadBuilder.class);
        Mockito.when(mockWSO2LoginBuilder.getEventSchemaType()).thenReturn(EventSchema.WSO2);
        Mockito.when(mockUserOperationEventPayloadBuilder.getEventSchemaType()).thenReturn(EventSchema.WSO2);
        Mockito.when(mockRegistrationEventPayloadBuilder.getEventSchemaType()).thenReturn(EventSchema.WSO2);
        Mockito.when(mockCAEPSessionBuilder.getEventSchemaType()).thenReturn(EventSchema.CAEP);
        Mockito.when(mockCAEPCredentialBuilder.getEventSchemaType()).thenReturn(EventSchema.CAEP);
        Mockito.when(mockCAEPVerificationBuilder.getEventSchemaType()).thenReturn(EventSchema.CAEP);

        EventHookHandlerDataHolder.getInstance().addLoginEventPayloadBuilder(mockWSO2LoginBuilder);
        EventHookHandlerDataHolder.getInstance().addSessionEventPayloadBuilder(mockCAEPSessionBuilder);
        EventHookHandlerDataHolder.getInstance().addCredentialEventPayloadBuilder(mockCAEPCredentialBuilder);
        EventHookHandlerDataHolder.getInstance()
                .addUserOperationEventPayloadBuilder(mockUserOperationEventPayloadBuilder);
        EventHookHandlerDataHolder.getInstance()
                .addRegistrationEventPayloadBuilder(mockRegistrationEventPayloadBuilder);
        EventHookHandlerDataHolder.getInstance().addVerificationEventPayloadBuilder(mockCAEPVerificationBuilder);
    }

    @Test
    public void testAddLoginEventPayloadBuilder() {

        List<LoginEventPayloadBuilder> builders =
                EventHookHandlerDataHolder.getInstance().getLoginEventPayloadBuilders();

        assertNotNull(builders, "The list of builders should not be null.");
        assertFalse(builders.isEmpty(), "The list of builders should not be empty.");
        assertTrue(builders.contains(mockWSO2LoginBuilder), "The mock builder should be in the list.");
    }

    @Test
    public void testAddUserOperationEventPayloadBuilder() {

        List<UserOperationEventPayloadBuilder> builders =
                EventHookHandlerDataHolder.getInstance().getUserOperationEventPayloadBuilders();

        assertNotNull(builders, "The list of builders should not be null.");
        assertFalse(builders.isEmpty(), "The list of builders should not be empty.");
        assertTrue(builders.contains(mockUserOperationEventPayloadBuilder), "The mock builder should be in the list.");
    }

    @Test
    public void testGetUserOperationEventPayloadBuilderReturnsRegisteredBuilder() {

        UserOperationEventPayloadBuilder builder = PayloadBuilderFactory.
                getUserOperationEventPayloadBuilder(EventSchema.WSO2);
        assertNotNull(builder, "The builder should not be null.");
        assertEquals(builder.getEventSchemaType(),
                EventSchema.WSO2, "The schema type should match 'WSO2'.");
    }

    @Test
    public void testAddRegistrationEventPayloadBuilder() {

        List<RegistrationEventPayloadBuilder> builders =
                EventHookHandlerDataHolder.getInstance().getRegistrationEventPayloadBuilders();

        assertNotNull(builders, "The list of builders should not be null.");
        assertFalse(builders.isEmpty(), "The list of builders should not be empty.");
        assertTrue(builders.contains(mockRegistrationEventPayloadBuilder), "The mock builder should be in the list.");
    }

    @Test
    public void testGetRegistrationEventPayloadBuilderReturnsRegisteredBuilder() {

        RegistrationEventPayloadBuilder builder =
                PayloadBuilderFactory.getRegistrationEventPayloadBuilder(EventSchema.WSO2);
        assertNotNull(builder, "The builder should not be null.");
        assertEquals(builder.getEventSchemaType(), EventSchema.WSO2, "The schema type should match 'WSO2'.");
    }

    @Test
    public void testGetLoginEventPayloadBuilderReturnsRegisteredBuilder() {

        LoginEventPayloadBuilder builder =
                PayloadBuilderFactory.getLoginEventPayloadBuilder(EventSchema.WSO2);
        assertNotNull(builder, "The builder should not be null.");
        assertEquals(builder.getEventSchemaType(),
                EventSchema.WSO2, "The schema type should match 'WSO2'.");
    }

    @Test
    public void testGetLoginEventPayloadBuilderUnknownSchema() {

        LoginEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getLoginEventPayloadBuilder(EventSchema.RISC);

        assertNull(payloadBuilder, "The builder should be null.");

    }

    @Test
    public void testGetSessionEventPayloadBuilderReturnsRegisteredBuilder() {

        SessionEventPayloadBuilder builder =
                PayloadBuilderFactory.getSessionEventPayloadBuilder(EventSchema.CAEP);
        assertNotNull(builder, "The builder should not be null.");
        assertEquals(builder.getEventSchemaType(),
                EventSchema.CAEP, "The schema type should match 'CAEP'.");
    }

    @Test
    public void testGetSessionEventPayloadBuilderUnknownSchema() {

        SessionEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getSessionEventPayloadBuilder(EventSchema.RISC);

        assertNull(payloadBuilder, "The builder should be null.");
    }

    @Test
    public void testGetCredentialEventPayloadBuilderReturnsRegisteredBuilder() {

        CredentialEventPayloadBuilder builder =
                PayloadBuilderFactory.getCredentialEventPayloadBuilder(EventSchema.CAEP);
        assertNotNull(builder, "The builder should not be null.");
        assertEquals(builder.getEventSchemaType(),
                EventSchema.CAEP, "The schema type should match 'CAEP'.");
    }

    @Test
    public void testGetCredentialEventPayloadBuilderUnknownSchema() {

        CredentialEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getCredentialEventPayloadBuilder(EventSchema.RISC);

        assertNull(payloadBuilder, "The builder should be null.");
    }

    @Test
    public void testGetVerificationEventPayloadBuilderReturnsRegisteredBuilder() {

        VerificationEventPayloadBuilder builder =
                PayloadBuilderFactory.getVerificationEventPayloadBuilder(EventSchema.CAEP);
        assertNotNull(builder, "The builder should not be null.");
        assertEquals(builder.getEventSchemaType(),
                EventSchema.CAEP, "The schema type should match 'CAEP'.");
    }

    @Test
    public void testGetVerificationEventPayloadBuilderUnknownSchema() {

        VerificationEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getVerificationEventPayloadBuilder(EventSchema.RISC);
        assertNull(payloadBuilder, "The builder should be null.");
    }

    @Test
    public void testGetUserOperationEventPayloadBuilderThrowsExceptionForUnknownSchema() {

        UserOperationEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getUserOperationEventPayloadBuilder(EventSchema.RISC);
        assertNull(payloadBuilder, "The builder should be null.");
    }

    @Test
    public void testGetRegistrationEventPayloadBuilderThrowsExceptionForUnknownSchema() {

        RegistrationEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getRegistrationEventPayloadBuilder(EventSchema.RISC);
        assertNull(payloadBuilder, "The builder should be null.");
    }
}
