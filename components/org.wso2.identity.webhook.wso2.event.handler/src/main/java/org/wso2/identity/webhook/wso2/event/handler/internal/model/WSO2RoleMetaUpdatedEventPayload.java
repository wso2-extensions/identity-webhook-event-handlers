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

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.RoleRef;

/**
 * Payload model for roleMetaUpdated events (role name change and other metadata mutations).
 */
public class WSO2RoleMetaUpdatedEventPayload extends WSO2AbstractRoleListEventPayload<RoleRef> {

    private WSO2RoleMetaUpdatedEventPayload(Builder builder) {

        super(builder);
    }

    /**
     * Builder for WSO2RoleMetaUpdatedEventPayload.
     */
    public static class Builder extends WSO2AbstractRoleListEventPayload.Builder<Builder, RoleRef> {

        @Override
        protected Builder self() {

            return this;
        }

        public WSO2RoleMetaUpdatedEventPayload build() {

            return new WSO2RoleMetaUpdatedEventPayload(this);
        }
    }
}
