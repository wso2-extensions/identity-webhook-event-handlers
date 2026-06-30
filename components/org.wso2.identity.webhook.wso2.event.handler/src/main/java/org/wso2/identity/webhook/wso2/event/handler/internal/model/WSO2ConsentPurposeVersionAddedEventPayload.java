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

import com.fasterxml.jackson.annotation.JsonInclude;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;

import java.util.List;

/**
 * Payload for the purpose version added event.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WSO2ConsentPurposeVersionAddedEventPayload extends WSO2BaseEventPayload {

    private final Purpose purpose;

    private WSO2ConsentPurposeVersionAddedEventPayload(Builder builder) {

        this.purpose = builder.purpose;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.action = builder.action;
        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
    }

    public Purpose getPurpose() {

        return purpose;
    }

    /**
     * Nested purpose object carrying id, name, and the new version details.
     */
    public static class Purpose {

        private final String id;
        private final String name;
        private final PurposeVersion version;

        public Purpose(String id, String name, PurposeVersion version) {

            this.id = id;
            this.name = name;
            this.version = version;
        }

        public String getId() {

            return id;
        }

        public String getName() {

            return name;
        }

        public PurposeVersion getVersion() {

            return version;
        }
    }

    /**
     * Version sub-object within the purpose.
     */
    public static class PurposeVersion {

        private final String version;
        private final boolean setAsLatest;
        private final List<PurposeElement> elements;

        public PurposeVersion(String version, boolean setAsLatest, List<PurposeElement> elements) {

            this.version = version;
            this.setAsLatest = setAsLatest;
            this.elements = elements;
        }

        public String getVersion() {

            return version;
        }

        public boolean isSetAsLatest() {

            return setAsLatest;
        }

        public List<PurposeElement> getElements() {

            return elements;
        }
    }

    /**
     * Element (PII category) within a purpose version.
     */
    public static class PurposeElement {

        private final String name;
        private final Boolean mandatory;

        public PurposeElement(String name, Boolean mandatory) {

            this.name = name;
            this.mandatory = mandatory;
        }

        public String getName() {

            return name;
        }

        public Boolean getMandatory() {

            return mandatory;
        }
    }

    public static class Builder {

        private Purpose purpose;
        private Tenant tenant;
        private Organization organization;
        private String action;
        private String initiatorType;
        private String initiatorIpAddress;

        public Builder purpose(Purpose purpose) {

            this.purpose = purpose;
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

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder initiatorIpAddress(String initiatorIpAddress) {

            this.initiatorIpAddress = initiatorIpAddress;
            return this;
        }

        public WSO2ConsentPurposeVersionAddedEventPayload build() {

            return new WSO2ConsentPurposeVersionAddedEventPayload(this);
        }
    }
}
