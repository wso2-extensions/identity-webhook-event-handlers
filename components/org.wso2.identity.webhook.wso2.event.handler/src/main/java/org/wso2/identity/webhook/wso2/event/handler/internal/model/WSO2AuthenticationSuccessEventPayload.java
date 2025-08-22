/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.ArrayList;
import java.util.List;

/**
 * Model Class for Authentication Success Event Payload.
 */
public class WSO2AuthenticationSuccessEventPayload extends WSO2BaseEventPayload {

    private List<String> authenticationMethods = new ArrayList<>();

    private WSO2AuthenticationSuccessEventPayload(Builder builder) {

        this.user = builder.user;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.userStore = builder.userStore;
        this.application = builder.application;
        this.initiatorType = builder.initiatorType;
        this.action = builder.action;
        this.authenticationMethods = builder.authenticationMethods;
    }

    public List<String> getAuthenticationMethods() {

        return authenticationMethods;
    }

    /**
     * Builder class to build WSO2AuthenticationSuccessEventPayload.
     */
    public static class Builder {

        private User user;
        private Tenant tenant;
        private Organization organization;
        private UserStore userStore;
        private Application application;
        private String initiatorType;
        private String action;
        private List<String> authenticationMethods = new ArrayList<>();

        public Builder user(User user) {

            this.user = user;
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

        public Builder userStore(UserStore userStore) {

            this.userStore = userStore;
            return this;
        }

        public Builder application(Application application) {

            this.application = application;
            return this;
        }

        public Builder authenticationMethods(List<String> authenticationMethods) {

            this.authenticationMethods = authenticationMethods;
            return this;
        }

        public Builder addAuthenticationMethod(String authenticationMethod) {

            this.authenticationMethods.add(authenticationMethod);
            return this;
        }

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder action(String action) {

            this.action = action;
            return this;
        }

        public WSO2AuthenticationSuccessEventPayload build() {

            return new WSO2AuthenticationSuccessEventPayload(this);
        }
    }
}
