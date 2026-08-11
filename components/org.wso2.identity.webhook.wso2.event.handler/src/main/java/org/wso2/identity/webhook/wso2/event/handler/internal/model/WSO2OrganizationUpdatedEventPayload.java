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

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.OrganizationRef;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.OrganizationChange;

import java.util.List;

/**
 * Payload model for the organizationUpdated event. Carries the organization context where the event was
 * triggered, the details of the updated organization and the changes applied to it.
 */
public class WSO2OrganizationUpdatedEventPayload extends WSO2BaseEventPayload {

    private final OrganizationRef updatedOrganization;
    private final List<OrganizationChange> changes;

    private WSO2OrganizationUpdatedEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.action = builder.action;
        this.updatedOrganization = builder.updatedOrganization;
        this.changes = builder.changes;
    }

    public OrganizationRef getUpdatedOrganization() {

        return updatedOrganization;
    }

    public List<OrganizationChange> getChanges() {

        return changes;
    }

    /**
     * Builder for WSO2OrganizationUpdatedEventPayload.
     */
    public static class Builder {

        private String initiatorType;
        private String initiatorIpAddress;
        private Tenant tenant;
        private Organization organization;
        private String action;
        private OrganizationRef updatedOrganization;
        private List<OrganizationChange> changes;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder initiatorIpAddress(String initiatorIpAddress) {

            this.initiatorIpAddress = initiatorIpAddress;
            return this;
        }

        public Builder tenant(Tenant tenant) {

            this.tenant = tenant;
            return this;
        }

        public Builder organization(Organization organization) {

            this.organization = organization;
            return this;
        }

        public Builder action(String action) {

            this.action = action;
            return this;
        }

        public Builder updatedOrganization(OrganizationRef updatedOrganization) {

            this.updatedOrganization = updatedOrganization;
            return this;
        }

        public Builder changes(List<OrganizationChange> changes) {

            this.changes = changes;
            return this;
        }

        public WSO2OrganizationUpdatedEventPayload build() {

            return new WSO2OrganizationUpdatedEventPayload(this);
        }
    }
}
