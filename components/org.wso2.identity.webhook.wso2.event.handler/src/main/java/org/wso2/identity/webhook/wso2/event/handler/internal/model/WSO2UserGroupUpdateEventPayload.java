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

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Group;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

/**
 * Model Class for user group update events in WSO2.
 */
public class WSO2UserGroupUpdateEventPayload extends WSO2BaseEventPayload {

    private Group group;

    private WSO2UserGroupUpdateEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.group = builder.group;
        this.organization = builder.organization;
        this.userStore = builder.userStore;
        this.tenant = builder.tenant;
    }

    public Group getGroup() {

        return group;
    }

    /**
     * Builder class to build WSO2UserGroupUpdateEventPayload.
     */
    public static class Builder {

        private String initiatorType;
        private Group group;
        private Organization organization;
        private UserStore userStore;
        private Tenant tenant;

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

        public Builder group(Group group) {

            this.group = group;
            return this;
        }

        public Builder tenant(Tenant tenant) {

            this.tenant = tenant;
            return this;
        }

        public WSO2UserGroupUpdateEventPayload build() {

            return new WSO2UserGroupUpdateEventPayload(this);
        }
    }
}
