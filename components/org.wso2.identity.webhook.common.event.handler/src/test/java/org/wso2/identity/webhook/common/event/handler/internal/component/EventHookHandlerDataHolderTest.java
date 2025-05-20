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

package org.wso2.identity.webhook.common.event.handler.internal.component;

import org.testng.annotations.Test;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertSame;

/**
 * Test class for EventHookHandlerDataHolder.
 */
public class EventHookHandlerDataHolderTest {

    @Test
    public void testSingletonInstance() {

        EventHookHandlerDataHolder instance1 = EventHookHandlerDataHolder.getInstance();
        EventHookHandlerDataHolder instance2 = EventHookHandlerDataHolder.getInstance();
        assertNotNull(instance1, "Instance should not be null");
        assertSame(instance1, instance2, "Both instances should be the same (singleton)");
    }

}
