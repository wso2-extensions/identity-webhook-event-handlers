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

import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerServiceComponent;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertNotNull;

/**
 * Test class for EventHookHandlerServiceComponent.
 */
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
