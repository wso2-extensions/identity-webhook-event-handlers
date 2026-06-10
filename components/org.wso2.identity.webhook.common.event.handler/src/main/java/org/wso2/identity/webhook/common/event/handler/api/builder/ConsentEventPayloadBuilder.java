/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.List;

/**
 * Interface for Consent Event Payload Builder.
 */
public interface ConsentEventPayloadBuilder {

    /**
     * Build one payload per purpose for a consent added event.
     * If the receipt covers multiple purposes, one payload is returned per purpose.
     *
     * @param eventData Event data.
     * @return List of event payloads, one per purpose.
     */
    List<EventPayload> buildConsentAddedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build one payload per purpose for a consent revoked event.
     * If the receipt covers multiple purposes, one payload is returned per purpose.
     *
     * @param eventData Event data.
     * @return List of event payloads, one per purpose.
     */
    List<EventPayload> buildConsentRevokedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Get the event schema type.
     *
     * @return Event schema type.
     */
    Constants.EventSchema getEventSchemaType();
}
