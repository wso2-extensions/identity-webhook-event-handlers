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

public class WSO2UserAccountEventPayload extends WSO2BaseEventPayload {

    private String action;

    public String getAction() {

        return action;
    }

    public void setAction(String action) {

        this.action = action;
    }

    private WSO2UserAccountEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.organization = builder.organization;
        this.user = builder.user;
        this.userStore = builder.userStore;
        this.tenant = builder.tenant;
        this.action = builder.action;
    }

    /**
     * Builder class to build WSO2UserDeleteEventPayload.
     */
    public static class Builder {

        private String initiatorType;
        private User user;
        private Organization organization;
        private UserStore userStore;
        private Organization tenant;
        private String action;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
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

        public Builder tenant(Organization tenant) {

            this.tenant = tenant;
            return this;
        }

        public Builder action(String action) {

            this.action = action;
            return this;
        }

        public WSO2UserAccountEventPayload build() {

            return new WSO2UserAccountEventPayload(this);
        }
    }
}
