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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

public class WSO2SessionCreatedEventPayload extends WSO2BaseEventPayload {

    private String sessionId;
    private String currentAcr;
    private Application application;

    public String getSessionId() {

        return sessionId;
    }

    public String getCurrentAcr() {

        return currentAcr;
    }

    @Override
    public Application getApplication() {

        return application;
    }

    private WSO2SessionCreatedEventPayload(Builder builder) {

        this.user = builder.user;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.userStore = builder.userStore;
        this.application = builder.application;
        this.sessionId = builder.sessionId;
        this.currentAcr = builder.currentAcr;
    }

    private WSO2SessionCreatedEventPayload() {

    }

    public static class Builder {

        private String sessionId;
        private String currentAcr;
        private User user;
        private Organization tenant;
        private Organization organization;
        private UserStore userStore;
        private Application application;

        public Builder sessionId(String sessionId) {

            this.sessionId = sessionId;
            return this;
        }

        public Builder currentAcr(String currentAcr) {

            this.currentAcr = currentAcr;
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

        public Builder application(Application application) {

            this.application = application;
            return this;
        }

        public WSO2SessionCreatedEventPayload build() {

            return new WSO2SessionCreatedEventPayload(this);
        }
    }

}
