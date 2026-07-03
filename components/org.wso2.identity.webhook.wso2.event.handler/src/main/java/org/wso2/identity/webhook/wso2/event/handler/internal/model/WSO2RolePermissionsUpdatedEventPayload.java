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

package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.RoleRef;

import java.util.List;

/**
 * Payload model for rolePermissionsUpdated events.
 * Added/removed permission lists (as permission name strings) are nested inside the role block.
 */
public class WSO2RolePermissionsUpdatedEventPayload
        extends WSO2AbstractRoleListEventPayload<WSO2RolePermissionsUpdatedEventPayload.RoleWithPermissions> {

    private WSO2RolePermissionsUpdatedEventPayload(Builder builder) {

        super(builder);
    }

    /**
     * Builder for WSO2RolePermissionsUpdatedEventPayload.
     */
    public static class Builder
            extends WSO2AbstractRoleListEventPayload.Builder<Builder, RoleWithPermissions> {

        @Override
        protected Builder self() {

            return this;
        }

        public WSO2RolePermissionsUpdatedEventPayload build() {

            return new WSO2RolePermissionsUpdatedEventPayload(this);
        }
    }

    /**
     * Role block for rolePermissionsUpdated events, carrying added/removed permission name strings.
     * Inherits id / name / audience / ref from {@link RoleRef}.
     */
    public static class RoleWithPermissions extends RoleRef {

        private List<String> addedPermissions;
        private List<String> removedPermissions;

        public List<String> getAddedPermissions() {

            return addedPermissions;
        }

        public void setAddedPermissions(List<String> addedPermissions) {

            this.addedPermissions = addedPermissions;
        }

        public List<String> getRemovedPermissions() {

            return removedPermissions;
        }

        public void setRemovedPermissions(List<String> removedPermissions) {

            this.removedPermissions = removedPermissions;
        }
    }
}
