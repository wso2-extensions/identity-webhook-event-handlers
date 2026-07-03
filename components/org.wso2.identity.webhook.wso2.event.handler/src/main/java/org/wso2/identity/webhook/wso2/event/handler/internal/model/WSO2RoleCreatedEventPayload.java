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
 * Payload model for roleCreated events.
 */
public class WSO2RoleCreatedEventPayload
        extends WSO2AbstractRoleListEventPayload<WSO2RoleCreatedEventPayload.RoleWithMembership> {

    private WSO2RoleCreatedEventPayload(Builder builder) {

        super(builder);
    }

    /**
     * Builder for WSO2RoleCreatedEventPayload.
     */
    public static class Builder
            extends WSO2AbstractRoleListEventPayload.Builder<Builder, RoleWithMembership> {

        @Override
        protected Builder self() {

            return this;
        }

        public WSO2RoleCreatedEventPayload build() {

            return new WSO2RoleCreatedEventPayload(this);
        }
    }

    /**
     * Role block for roleCreated events, carrying initial membership and permissions.
     * Inherits id / name / audience / ref from {@link RoleRef}.
     */
    public static class RoleWithMembership extends RoleRef {

        private List<UserEntry> users;
        private List<GroupEntry> groups;
        private List<String> permissions;

        public List<UserEntry> getUsers() {

            return users;
        }

        public void setUsers(List<UserEntry> users) {

            this.users = users;
        }

        public List<GroupEntry> getGroups() {

            return groups;
        }

        public void setGroups(List<GroupEntry> groups) {

            this.groups = groups;
        }

        public List<String> getPermissions() {

            return permissions;
        }

        public void setPermissions(List<String> permissions) {

            this.permissions = permissions;
        }
    }
}
