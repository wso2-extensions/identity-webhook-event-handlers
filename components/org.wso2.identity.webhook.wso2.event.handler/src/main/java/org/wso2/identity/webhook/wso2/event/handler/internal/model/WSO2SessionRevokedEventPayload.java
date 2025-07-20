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

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Session;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.List;

public class WSO2SessionRevokedEventPayload extends WSO2BaseEventPayload {

    private String initiatorType;
    private String sessionId;
    private List<Session> sessions;

    private WSO2SessionRevokedEventPayload(Builder builder) {

        this.user = builder.user;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.userStore = builder.userStore;
        this.initiatorType = builder.initiatorType;
        this.sessionId = builder.sessionId;
        this.sessions = builder.sessions;
    }

    public String getInitiatorType() {

        return initiatorType;
    }

    public String getSessionId() {

        return sessionId;
    }

    public List<Session> getSessions() {

        return sessions;
    }

    private WSO2SessionRevokedEventPayload() {

    }

    public static class Builder {

        private User user;
        private Organization tenant;
        private Organization organization;
        private UserStore userStore;
        private String initiatorType;
        private String sessionId;
        private List<Session> sessions;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder sessionId(String sessionId) {

            this.sessionId = sessionId;
            return this;
        }

        public Builder user(User user) {

            this.user = user;
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

        public Builder sessions(List<Session> sessions) {

            this.sessions = sessions;
            return this;
        }

        public WSO2SessionRevokedEventPayload build() {

            return new WSO2SessionRevokedEventPayload(this);
        }
    }
}
