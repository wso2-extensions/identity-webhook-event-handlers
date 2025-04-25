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

import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;

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

    /**
     * Get the session event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Session event payload builder.
     */
    public static SessionEventPayloadBuilder getSessionEventPayloadBuilder(String eventSchemaType) {

        List<SessionEventPayloadBuilder> sessionEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getSessionEventPayloadBuilders();
        for (SessionEventPayloadBuilder sessionEventPayloadBuilder : sessionEventPayloadBuilders) {
            if (sessionEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return sessionEventPayloadBuilder;
            }
        }
        throw new IllegalArgumentException("Unknown schema: " + eventSchemaType);
    }

    /**
     * Get the credential event payload builder.
     *
     * @param eventSchemaType Event schema type.
     * @return Credential event payload builder.
     */
    public static CredentialEventPayloadBuilder getCredentialEventPayloadBuilder(
            String eventSchemaType) {

        List<CredentialEventPayloadBuilder> credentialEventPayloadBuilders =
                EventHookHandlerDataHolder.getInstance().getCredentialEventPayloadBuilders();
        for (CredentialEventPayloadBuilder credentialEventPayloadBuilder : credentialEventPayloadBuilders) {
            if (credentialEventPayloadBuilder.getEventSchemaType().equals(eventSchemaType)) {
                return credentialEventPayloadBuilder;
            }
        }
        throw new IllegalArgumentException("Unknown schema: " + eventSchemaType);
    }
}
