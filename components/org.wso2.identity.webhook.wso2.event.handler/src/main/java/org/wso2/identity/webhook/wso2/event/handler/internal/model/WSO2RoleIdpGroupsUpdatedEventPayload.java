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
 * Payload model for roleIdpGroupsUpdated events.
 * Added/removed IdP group lists and truncation metadata are nested inside the role block.
 */
public class WSO2RoleIdpGroupsUpdatedEventPayload
        extends WSO2AbstractRoleListEventPayload<WSO2RoleIdpGroupsUpdatedEventPayload.RoleWithIdpGroups> {

    private WSO2RoleIdpGroupsUpdatedEventPayload(Builder builder) {

        super(builder);
    }

    /**
     * Builder for WSO2RoleIdpGroupsUpdatedEventPayload.
     */
    public static class Builder
            extends WSO2AbstractRoleListEventPayload.Builder<Builder, RoleWithIdpGroups> {

        @Override
        protected Builder self() {

            return this;
        }

        public WSO2RoleIdpGroupsUpdatedEventPayload build() {

            return new WSO2RoleIdpGroupsUpdatedEventPayload(this);
        }
    }

    /**
     * Role block for roleIdpGroupsUpdated events, carrying capped added/removed IdP group lists
     * with optional truncation metadata. Inherits id / name / audience / ref from {@link RoleRef}.
     */
    public static class RoleWithIdpGroups extends RoleRef {

        private List<IdpGroupEntry> addedIdpGroups;
        private List<IdpGroupEntry> removedIdpGroups;
        private Boolean addedIdpGroupsTruncated;
        private Integer addedIdpGroupsTotalCount;
        private String addedIdpGroupsRef;
        private Boolean removedIdpGroupsTruncated;
        private Integer removedIdpGroupsTotalCount;
        private String removedIdpGroupsRef;

        public List<IdpGroupEntry> getAddedIdpGroups() {

            return addedIdpGroups;
        }

        public void setAddedIdpGroups(List<IdpGroupEntry> addedIdpGroups) {

            this.addedIdpGroups = addedIdpGroups;
        }

        public List<IdpGroupEntry> getRemovedIdpGroups() {

            return removedIdpGroups;
        }

        public void setRemovedIdpGroups(List<IdpGroupEntry> removedIdpGroups) {

            this.removedIdpGroups = removedIdpGroups;
        }

        public Boolean getAddedIdpGroupsTruncated() {

            return addedIdpGroupsTruncated;
        }

        public void setAddedIdpGroupsTruncated(Boolean addedIdpGroupsTruncated) {

            this.addedIdpGroupsTruncated = addedIdpGroupsTruncated;
        }

        public Integer getAddedIdpGroupsTotalCount() {

            return addedIdpGroupsTotalCount;
        }

        public void setAddedIdpGroupsTotalCount(Integer addedIdpGroupsTotalCount) {

            this.addedIdpGroupsTotalCount = addedIdpGroupsTotalCount;
        }

        public String getAddedIdpGroupsRef() {

            return addedIdpGroupsRef;
        }

        public void setAddedIdpGroupsRef(String addedIdpGroupsRef) {

            this.addedIdpGroupsRef = addedIdpGroupsRef;
        }

        public Boolean getRemovedIdpGroupsTruncated() {

            return removedIdpGroupsTruncated;
        }

        public void setRemovedIdpGroupsTruncated(Boolean removedIdpGroupsTruncated) {

            this.removedIdpGroupsTruncated = removedIdpGroupsTruncated;
        }

        public Integer getRemovedIdpGroupsTotalCount() {

            return removedIdpGroupsTotalCount;
        }

        public void setRemovedIdpGroupsTotalCount(Integer removedIdpGroupsTotalCount) {

            this.removedIdpGroupsTotalCount = removedIdpGroupsTotalCount;
        }

        public String getRemovedIdpGroupsRef() {

            return removedIdpGroupsRef;
        }

        public void setRemovedIdpGroupsRef(String removedIdpGroupsRef) {

            this.removedIdpGroupsRef = removedIdpGroupsRef;
        }
    }

    /**
     * Represents an IdP group entry with groupId, groupName, idpId and idpName.
     */
    public static class IdpGroupEntry {

        private String groupId;
        private String groupName;
        private String idpId;
        private String idpName;

        public IdpGroupEntry(String groupId, String groupName, String idpId, String idpName) {

            this.groupId = groupId;
            this.groupName = groupName;
            this.idpId = idpId;
            this.idpName = idpName;
        }

        public String getGroupId() {

            return groupId;
        }

        public String getGroupName() {

            return groupName;
        }

        public String getIdpId() {

            return idpId;
        }

        public String getIdpName() {

            return idpName;
        }
    }
}
