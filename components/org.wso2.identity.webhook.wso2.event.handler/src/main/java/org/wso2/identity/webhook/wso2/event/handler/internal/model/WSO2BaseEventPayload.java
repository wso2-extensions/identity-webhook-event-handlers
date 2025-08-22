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

import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

/**
 * Base class for WSO2 Event Payload.
 */
public abstract class WSO2BaseEventPayload extends EventPayload {

    protected String initiatorType;
    protected User user;
    protected Tenant tenant;
    protected Organization organization;
    protected UserStore userStore;
    protected Application application;
    protected String action;

    public User getUser() {

        return user;
    }

    public Tenant getTenant() {

        return tenant;
    }

    public UserStore getUserStore() {

        return userStore;
    }

    public Application getApplication() {

        return application;
    }

    public Organization getOrganization() {

        return organization;
    }

    public String getInitiatorType() {

        return initiatorType;
    }

    public String getAction() {

        return action;
    }
}
