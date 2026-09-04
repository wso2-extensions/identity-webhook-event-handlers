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

/**
 * Payload model for the organizationDeleted event. Carries the organization context where the event was
 * triggered and a reference to the deleted organization.
 */
public class WSO2OrganizationDeletedEventPayload extends WSO2BaseEventPayload {

    private final OrganizationRef deletedOrganization;

    private WSO2OrganizationDeletedEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.action = builder.action;
        this.deletedOrganization = builder.deletedOrganization;
    }

    public OrganizationRef getDeletedOrganization() {

        return deletedOrganization;
    }

    /**
     * Builder for WSO2OrganizationDeletedEventPayload.
     */
    public static class Builder {

        private String initiatorType;
        private String initiatorIpAddress;
        private Tenant tenant;
        private Organization organization;
        private String action;
        private OrganizationRef deletedOrganization;

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

        public Builder deletedOrganization(OrganizationRef deletedOrganization) {

            this.deletedOrganization = deletedOrganization;
            return this;
        }

        public WSO2OrganizationDeletedEventPayload build() {

            return new WSO2OrganizationDeletedEventPayload(this);
        }
    }
}
