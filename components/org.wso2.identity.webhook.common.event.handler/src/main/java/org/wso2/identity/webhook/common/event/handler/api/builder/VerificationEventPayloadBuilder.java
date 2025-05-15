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

package org.wso2.identity.webhook.common.event.handler.api.builder;

import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

/**
 * This interface defines the contract for building verification event payloads.
 * Implementations of this interface should provide the logic to build the payload
 * for different types of verification events.
 */
public interface VerificationEventPayloadBuilder {

    /**
     * Build the verification event payload.
     *
     * @param eventData Event Data.
     * @return The verification event payload.
     */
    EventPayload buildVerificationEventPayload(EventData eventData);

    /**
     * Get the verification event schema type.
     *
     * @return The verification event schema type.
     */
    EventSchema getEventSchemaType();

}
