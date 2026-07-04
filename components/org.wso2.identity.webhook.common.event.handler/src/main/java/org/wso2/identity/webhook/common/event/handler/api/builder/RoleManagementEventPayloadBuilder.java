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
 * Interface for Role Management Event Payload Builders.
 */
public interface RoleManagementEventPayloadBuilder {

    /**
     * Build the payload for a role-created event.
     *
     * @param eventData Event data from the Carbon event.
     * @return EventPayload for the roleCreated webhook event.
     * @throws IdentityEventException if payload building fails.
     */
    EventPayload buildRoleCreatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload for a role-meta-updated event (name change and other metadata mutations).
     *
     * @param eventData Event data from the Carbon event.
     * @return EventPayload for the roleMetaUpdated webhook event.
     * @throws IdentityEventException if payload building fails.
     */
    EventPayload buildRoleMetaUpdatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload for a role-deleted event.
     *
     * @param eventData Event data from the Carbon event.
     * @return EventPayload for the roleDeleted webhook event.
     * @throws IdentityEventException if payload building fails.
     */
    EventPayload buildRoleDeletedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload for a role user-list updated event.
     *
     * @param eventData Event data from the Carbon event.
     * @return EventPayload for the roleUsersUpdated webhook event.
     * @throws IdentityEventException if payload building fails.
     */
    EventPayload buildRoleUsersUpdatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload for a role group-list updated event.
     *
     * @param eventData Event data from the Carbon event.
     * @return EventPayload for the roleGroupsUpdated webhook event.
     * @throws IdentityEventException if payload building fails.
     */
    EventPayload buildRoleGroupsUpdatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload for a role IdP-group-list updated event.
     *
     * @param eventData Event data from the Carbon event.
     * @return EventPayload for the roleIdpGroupsUpdated webhook event.
     * @throws IdentityEventException if payload building fails.
     */
    EventPayload buildRoleIdpGroupsUpdatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Build the payload for a role permissions updated event.
     *
     * @param eventData Event data from the Carbon event.
     * @return EventPayload for the rolePermissionsUpdated webhook event.
     * @throws IdentityEventException if payload building fails.
     */
    EventPayload buildRolePermissionsUpdatedEvent(EventData eventData) throws IdentityEventException;

    /**
     * Return the event schema type this builder implements.
     *
     * @return Event schema type.
     */
    Constants.EventSchema getEventSchemaType();
}
