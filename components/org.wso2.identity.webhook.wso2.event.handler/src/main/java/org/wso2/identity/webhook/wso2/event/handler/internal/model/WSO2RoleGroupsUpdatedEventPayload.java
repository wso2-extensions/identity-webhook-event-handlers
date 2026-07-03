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
 * Payload model for roleGroupsUpdated events.
 * Added/removed group lists and truncation metadata are nested inside the role block.
 */
public class WSO2RoleGroupsUpdatedEventPayload
        extends WSO2AbstractRoleListEventPayload<WSO2RoleGroupsUpdatedEventPayload.RoleWithGroups> {

    private WSO2RoleGroupsUpdatedEventPayload(Builder builder) {

        super(builder);
    }

    /**
     * Builder for WSO2RoleGroupsUpdatedEventPayload.
     */
    public static class Builder
            extends WSO2AbstractRoleListEventPayload.Builder<Builder, RoleWithGroups> {

        @Override
        protected Builder self() {

            return this;
        }

        public WSO2RoleGroupsUpdatedEventPayload build() {

            return new WSO2RoleGroupsUpdatedEventPayload(this);
        }
    }

    /**
     * Role block for roleGroupsUpdated events, carrying capped added/removed group lists
     * with optional truncation metadata. Inherits id / name / audience / ref from {@link RoleRef}.
     */
    public static class RoleWithGroups extends RoleRef {

        private List<GroupEntry> addedGroups;
        private List<GroupEntry> removedGroups;
        private Boolean addedGroupsTruncated;
        private Integer addedGroupsTotalCount;
        private String addedGroupsRef;
        private Boolean removedGroupsTruncated;
        private Integer removedGroupsTotalCount;
        private String removedGroupsRef;

        public List<GroupEntry> getAddedGroups() {

            return addedGroups;
        }

        public void setAddedGroups(List<GroupEntry> addedGroups) {

            this.addedGroups = addedGroups;
        }

        public List<GroupEntry> getRemovedGroups() {

            return removedGroups;
        }

        public void setRemovedGroups(List<GroupEntry> removedGroups) {

            this.removedGroups = removedGroups;
        }

        public Boolean getAddedGroupsTruncated() {

            return addedGroupsTruncated;
        }

        public void setAddedGroupsTruncated(Boolean addedGroupsTruncated) {

            this.addedGroupsTruncated = addedGroupsTruncated;
        }

        public Integer getAddedGroupsTotalCount() {

            return addedGroupsTotalCount;
        }

        public void setAddedGroupsTotalCount(Integer addedGroupsTotalCount) {

            this.addedGroupsTotalCount = addedGroupsTotalCount;
        }

        public String getAddedGroupsRef() {

            return addedGroupsRef;
        }

        public void setAddedGroupsRef(String addedGroupsRef) {

            this.addedGroupsRef = addedGroupsRef;
        }

        public Boolean getRemovedGroupsTruncated() {

            return removedGroupsTruncated;
        }

        public void setRemovedGroupsTruncated(Boolean removedGroupsTruncated) {

            this.removedGroupsTruncated = removedGroupsTruncated;
        }

        public Integer getRemovedGroupsTotalCount() {

            return removedGroupsTotalCount;
        }

        public void setRemovedGroupsTotalCount(Integer removedGroupsTotalCount) {

            this.removedGroupsTotalCount = removedGroupsTotalCount;
        }

        public String getRemovedGroupsRef() {

            return removedGroupsRef;
        }

        public void setRemovedGroupsRef(String removedGroupsRef) {

            this.removedGroupsRef = removedGroupsRef;
        }
    }
}
