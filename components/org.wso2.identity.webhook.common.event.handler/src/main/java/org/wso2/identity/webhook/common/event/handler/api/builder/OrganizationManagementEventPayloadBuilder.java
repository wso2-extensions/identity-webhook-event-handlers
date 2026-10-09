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

/**
 * Interface for Organization Event Payload Builder.
 */
public interface OrganizationManagementEventPayloadBuilder {

    /**
     * Build the organization created event.
     *
     * @param eventData Event data which contains the data for organization creation.
     * @return Event payload built from the event data.
     * @throws IdentityEventException throws when an error is occurred.
     */
    EventPayload buildOrganizationCreatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the organization updated event.
     * <p>
     * Implementations return null when the update changed nothing that belongs in this event, so that an update
     * which only changed the status of the organization is published as the organization status changed event alone.
     *
     * @param eventData Event data which contains the data for organization update.
     * @return Event payload built from the event data, or null when the update carries no values for this event.
     * @throws IdentityEventException throws when an error is occurred.
     */
    EventPayload buildOrganizationUpdatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the organization delete event.
     *
     * @param eventData Event data which contains the data for organization delete.
     * @return Event payload built from the event data.
     * @throws IdentityEventException throws when an error is occurred.
     */
    EventPayload buildOrganizationDeletedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the organization activated event.
     * <p>
     * The event is published when an update activated the organization, in addition to the organization updated
     * event when the update changed other values as well.
     *
     * @param eventData Event data which contains the data for organization update.
     * @return Event payload built from the event data.
     * @throws IdentityEventException throws when an error is occurred.
     */
    EventPayload buildOrganizationActivatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the organization disabled event.
     * <p>
     * The event is published when an update disabled the organization, in addition to the organization updated
     * event when the update changed other values as well.
     *
     * @param eventData Event data which contains the data for organization update.
     * @return Event payload built from the event data.
     * @throws IdentityEventException throws when an error is occurred.
     */
    EventPayload buildOrganizationDisabledEvent(EventData eventData) throws IdentityEventException;

    /**
     * Get the event schema type.
     *
     * @return Event schema type.
     */
    Constants.EventSchema getEventSchemaType();
}
