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
 * Payload model for roleUsersUpdated events.
 * Added/removed user lists and truncation metadata are nested inside the role block.
 */
public class WSO2RoleUsersUpdatedEventPayload
        extends WSO2AbstractRoleListEventPayload<WSO2RoleUsersUpdatedEventPayload.RoleWithUsers> {

    private WSO2RoleUsersUpdatedEventPayload(Builder builder) {

        super(builder);
    }

    /**
     * Builder for WSO2RoleUsersUpdatedEventPayload.
     */
    public static class Builder
            extends WSO2AbstractRoleListEventPayload.Builder<Builder, RoleWithUsers> {

        @Override
        protected Builder self() {

            return this;
        }

        public WSO2RoleUsersUpdatedEventPayload build() {

            return new WSO2RoleUsersUpdatedEventPayload(this);
        }
    }

    /**
     * Role block for roleUsersUpdated events, carrying capped added/removed user lists
     * with optional truncation metadata. Inherits id / name / audience / ref from {@link RoleRef}.
     */
    public static class RoleWithUsers extends RoleRef {

        private List<UserEntry> addedUsers;
        private List<UserEntry> removedUsers;
        private Boolean addedUsersTruncated;
        private Integer addedUsersTotalCount;
        private String addedUsersRef;
        private Boolean removedUsersTruncated;
        private Integer removedUsersTotalCount;
        private String removedUsersRef;

        public List<UserEntry> getAddedUsers() {

            return addedUsers;
        }

        public void setAddedUsers(List<UserEntry> addedUsers) {

            this.addedUsers = addedUsers;
        }

        public List<UserEntry> getRemovedUsers() {

            return removedUsers;
        }

        public void setRemovedUsers(List<UserEntry> removedUsers) {

            this.removedUsers = removedUsers;
        }

        public Boolean getAddedUsersTruncated() {

            return addedUsersTruncated;
        }

        public void setAddedUsersTruncated(Boolean addedUsersTruncated) {

            this.addedUsersTruncated = addedUsersTruncated;
        }

        public Integer getAddedUsersTotalCount() {

            return addedUsersTotalCount;
        }

        public void setAddedUsersTotalCount(Integer addedUsersTotalCount) {

            this.addedUsersTotalCount = addedUsersTotalCount;
        }

        public String getAddedUsersRef() {

            return addedUsersRef;
        }

        public void setAddedUsersRef(String addedUsersRef) {

            this.addedUsersRef = addedUsersRef;
        }

        public Boolean getRemovedUsersTruncated() {

            return removedUsersTruncated;
        }

        public void setRemovedUsersTruncated(Boolean removedUsersTruncated) {

            this.removedUsersTruncated = removedUsersTruncated;
        }

        public Integer getRemovedUsersTotalCount() {

            return removedUsersTotalCount;
        }

        public void setRemovedUsersTotalCount(Integer removedUsersTotalCount) {

            this.removedUsersTotalCount = removedUsersTotalCount;
        }

        public String getRemovedUsersRef() {

            return removedUsersRef;
        }

        public void setRemovedUsersRef(String removedUsersRef) {

            this.removedUsersRef = removedUsersRef;
        }
    }
}
