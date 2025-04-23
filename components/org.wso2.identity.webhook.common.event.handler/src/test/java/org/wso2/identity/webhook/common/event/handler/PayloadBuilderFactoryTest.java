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

package org.wso2.identity.webhook.common.event.handler;

import org.mockito.Mockito;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.service.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.assertTrue;

/**
 * Test class for PayloadBuilderFactory.
 */
public class PayloadBuilderFactoryTest {

    private LoginEventPayloadBuilder mockBuilder;

    @BeforeClass
    public void setup() {

        mockBuilder = Mockito.mock(LoginEventPayloadBuilder.class);
        Mockito.when(mockBuilder.getEventSchemaType()).thenReturn(Constants.WSO2_EVENT_SCHEMA);

        EventHookHandlerDataHolder.getInstance().addLoginEventPayloadBuilder(mockBuilder);
    }

    @Test
    public void testAddLoginEventPayloadBuilder() {

        List<LoginEventPayloadBuilder> builders =
                EventHookHandlerDataHolder.getInstance().getLoginEventPayloadBuilders();

        assertNotNull(builders, "The list of builders should not be null.");
        assertFalse(builders.isEmpty(), "The list of builders should not be empty.");
        assertTrue(builders.contains(mockBuilder), "The mock builder should be in the list.");
    }

    @Test
    public void testGetLoginEventPayloadBuilderReturnsRegisteredBuilder() {

        LoginEventPayloadBuilder builder = PayloadBuilderFactory.getLoginEventPayloadBuilder(Constants.WSO2_EVENT_SCHEMA);
        assertNotNull(builder, "The builder should not be null.");
        assertEquals(builder.getEventSchemaType(), Constants.WSO2_EVENT_SCHEMA, "The schema type should match 'WSO2'.");
    }

    @Test
    public void testGetLoginEventPayloadBuilderThrowsExceptionForUnknownSchema() {

        assertThrows(IllegalArgumentException.class,
                () -> PayloadBuilderFactory.getLoginEventPayloadBuilder("UnknownSchema"));
    }
}
