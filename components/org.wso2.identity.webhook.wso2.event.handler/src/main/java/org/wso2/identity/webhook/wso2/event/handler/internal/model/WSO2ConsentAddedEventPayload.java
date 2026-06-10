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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Consent;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

/**
 * Payload for the consent added event.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WSO2ConsentAddedEventPayload extends WSO2BaseEventPayload {

    private final String subjectId;
    private final Consent consent;

    private WSO2ConsentAddedEventPayload(Builder builder) {

        this.subjectId = builder.subjectId;
        this.consent = builder.consent;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.user = builder.user;
        this.userStore = builder.userStore;
        this.action = builder.action;
        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
    }

    public String getSubjectId() {

        return subjectId;
    }

    public Consent getConsent() {

        return consent;
    }

    public static class Builder {

        private String subjectId;
        private Consent consent;
        private Tenant tenant;
        private Organization organization;
        private User user;
        private UserStore userStore;
        private String action;
        private String initiatorType;
        private String initiatorIpAddress;

        public Builder subjectId(String subjectId) {

            this.subjectId = subjectId;
            return this;
        }

        public Builder consent(Consent consent) {

            this.consent = consent;
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

        public Builder user(User user) {

            this.user = user;
            return this;
        }

        public Builder userStore(UserStore userStore) {

            this.userStore = userStore;
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

        public WSO2ConsentAddedEventPayload build() {

            return new WSO2ConsentAddedEventPayload(this);
        }
    }
}
