/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.List;

public class WSO2RegistrationInvitationEventPayload extends WSO2BaseEventPayload {

    private List<String> registrationMethods;
    private List<String> credentialsEnrolled;
    private String action;

    public List<String> getRegistrationMethods() {

        return registrationMethods;
    }

    public List<String> getCredentialsEnrolled() {

        return credentialsEnrolled;
    }

    public String getAction() {

        return action;
    }

    private WSO2RegistrationInvitationEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.userStore = builder.userStore;
        this.user = builder.user;
        this.registrationMethods = builder.registrationMethods;
        this.credentialsEnrolled = builder.credentialsEnrolled;
        this.action = builder.action;
    }

    public static class Builder {

        private String initiatorType;
        private Organization tenant;
        private Organization organization;
        private UserStore userStore;
        private User user;
        private List<String> registrationMethods;
        private List<String> credentialsEnrolled;
        private String action;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder action(String action) {

            this.action = action;
            return this;
        }

        public Builder tenant(Organization tenant) {

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

        public Builder user(User user) {

            this.user = user;
            return this;
        }

        public Builder registrationMethods(List<String> registrationMethods) {

            this.registrationMethods = registrationMethods;
            return this;
        }

        public Builder credentialsEnrolled(List<String> credentialsEnrolled) {

            this.credentialsEnrolled = credentialsEnrolled;
            return this;
        }

        public WSO2RegistrationInvitationEventPayload build() {

            return new WSO2RegistrationInvitationEventPayload(this);
        }

    }
}
