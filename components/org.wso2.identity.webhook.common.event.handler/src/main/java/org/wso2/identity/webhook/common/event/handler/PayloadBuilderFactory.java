/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.internal.EventHookHandlerDataHolder;

import java.util.List;

/**
 * Payload builder factory class.
 */
public class PayloadBuilderFactory {

    /**
     * Get the login event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Login event payload builder.
     */
    public static LoginEventPayloadBuilder getLoginEventPayloadBuilder(String eventSchemaType) {

        List<LoginEventPayloadBuilder> loginEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getLoginEventPayloadBuilders();
        for (LoginEventPayloadBuilder loginEventPayloadBuilder : loginEventPayloadBuilders) {
            if (loginEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return loginEventPayloadBuilder;
            }
        }
        throw new IllegalArgumentException("Unknown schema: " + eventSchemaType);
    }
}
