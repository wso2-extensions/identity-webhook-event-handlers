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

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.RoleRef;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;

/**
 * Common base for role list-updated events whose payload carries a specific
 * {@link RoleRef} subtype (users/groups/IdP groups) plus the standard envelope
 * fields. The self-typed {@link Builder} lets concrete subclasses expose a
 * fluent API without redeclaring every setter.
 *
 * @param <R> concrete role block type (e.g. {@code RoleWithUsers}, extends {@link RoleRef}).
 */
public abstract class WSO2AbstractRoleListEventPayload<R extends RoleRef> extends WSO2BaseEventPayload {

    protected R role;

    protected WSO2AbstractRoleListEventPayload(Builder<?, R> builder) {

        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.initiatorType = builder.initiatorType;
        this.initiatorIpAddress = builder.initiatorIpAddress;
        this.action = builder.action;
        this.role = builder.role;
    }

    public R getRole() {

        return role;
    }

    /**
     * Self-typed builder base for role list-updated events.
     */
    public abstract static class Builder<B extends Builder<B, R>, R extends RoleRef> {

        protected Tenant tenant;
        protected Organization organization;
        protected String initiatorType;
        protected String initiatorIpAddress;
        protected String action;
        protected R role;

        protected abstract B self();

        public B tenant(Tenant tenant) {

            this.tenant = tenant;
            return self();
        }

        public B organization(Organization organization) {

            this.organization = organization;
            return self();
        }

        public B initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return self();
        }

        public B initiatorIpAddress(String initiatorIpAddress) {

            this.initiatorIpAddress = initiatorIpAddress;
            return self();
        }

        public B action(String action) {

            this.action = action;
            return self();
        }

        public B role(R role) {

            this.role = role;
            return self();
        }
    }
}
