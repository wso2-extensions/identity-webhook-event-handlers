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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.List;

/**
 * Represents the payload for the WSO2 Token Revoked event.
 * This class encapsulates details about the revoked access tokens and other related information.
 */
public class WSO2TokenRevokedEventPayload extends WSO2BaseEventPayload {

    private List<AccessToken> accessTokens;

    public List<AccessToken> getAccessTokens() {

        return accessTokens;
    }

    private WSO2TokenRevokedEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.tenant = builder.tenant;
        this.userStore = builder.userStore;
        this.user = builder.user;
        this.accessTokens = builder.accessTokens;
        this.application = builder.application;
    }

    public static class Builder {

        private String initiatorType;
        private Tenant tenant;
        private UserStore userStore;
        private User user;
        private List<AccessToken> accessTokens;
        private Application application;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder tenant(Tenant tenant) {

            this.tenant = tenant;
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

        public Builder accessTokens(List<AccessToken> accessTokens) {

            this.accessTokens = accessTokens;
            return this;
        }

        public Builder application(Application application) {

            this.application = application;
            return this;
        }

        public WSO2TokenRevokedEventPayload build() {

            return new WSO2TokenRevokedEventPayload(this);
        }
    }
}
