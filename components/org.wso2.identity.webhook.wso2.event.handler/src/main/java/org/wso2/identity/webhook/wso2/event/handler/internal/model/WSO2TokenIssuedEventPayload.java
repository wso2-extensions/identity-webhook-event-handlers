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

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.AccessToken;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.List;

/**
 * Represents the payload for the WSO2 Token Issued event.
 * This class encapsulates details about the issued access token, scopes, and other related information.
 */
public class WSO2TokenIssuedEventPayload extends WSO2BaseEventPayload {

    private AccessToken accessToken;
    private List<String> scopes;
    private String action;

    public AccessToken getAccessToken() {

        return accessToken;
    }

    public List<String> getScopes() {

        return scopes;
    }

    public String getAction() {

        return action;
    }

    private WSO2TokenIssuedEventPayload(Builder builder) {

        this.accessToken = builder.accessToken;
        this.initiatorType = builder.initiatorType;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.userStore = builder.userStore;
        this.user = builder.user;
        this.application = builder.application;
        this.scopes = builder.scopes;
        this.action = builder.action;
    }

    public static class Builder {

        private String initiatorType;
        private Tenant tenant;
        private Organization organization;
        private UserStore userStore;
        private User user;
        private AccessToken accessToken;
        private Application application;
        private List<String> scopes;
        private String action;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
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

        public Builder user(User user) {

            this.user = user;
            return this;
        }

        public Builder accessToken(AccessToken accessToken) {

            this.accessToken = accessToken;
            return this;
        }

        public Builder application(Application application) {

            this.application = application;
            return this;
        }

        public Builder scopes(List<String> scopes) {

            this.scopes = scopes;
            return this;
        }

        public Builder action(String action) {

            this.action = action;
            return this;
        }

        public WSO2TokenIssuedEventPayload build() {

            return new WSO2TokenIssuedEventPayload(this);
        }
    }
}
