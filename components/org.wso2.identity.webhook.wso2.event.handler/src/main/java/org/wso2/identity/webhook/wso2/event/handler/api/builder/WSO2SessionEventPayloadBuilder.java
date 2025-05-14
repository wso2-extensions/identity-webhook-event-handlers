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

package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils.extractSessionId;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils.getUserResidentOrganization;

public class WSO2SessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    Log log = LogFactory.getLog(WSO2SessionEventPayloadBuilder.class);

    @Override
    public EventPayload buildSessionTerminateEvent(EventData eventData) throws IdentityEventException {
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        String tenantDomain = authenticatedUser.getTenantDomain();
        Map<String, Object> params = eventData.getEventParams();

        User user = new User();
        WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);

        Organization tenant = new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain)),
                tenantDomain);
        UserStore userStore = null;
        if (authenticatedUser.getUserStoreDomain() != null) {
            userStore = new UserStore(authenticatedUser.getUserStoreDomain());
        }
        Organization b2bUserResidentOrganization = null;
        if (authenticatedUser.getUserResidentOrganization() != null) {
            b2bUserResidentOrganization = getUserResidentOrganization(
                    authenticatedUser.getUserResidentOrganization());
        }

        List<Application> applications = new ArrayList<>();


        Object sessionData = params.getOrDefault("sessionData", null);

        if (sessionData != null) {

            if (sessionData instanceof String) {
                SessionContext sessionContext = getSessionContextFromSessionId((String) sessionData, tenantDomain);
                for (Map.Entry<String, Map<String, AuthenticatedIdPData>> application :
                        sessionContext.getAuthenticatedIdPsOfApp().entrySet()) {
                    applications.add(new Application(
                            null,
                            application.getKey()));
                }
            } else if (sessionData instanceof List) {
                for (String sessionId : (List<String>) sessionData) {
                    SessionContext sessionContext = getSessionContextFromSessionId(sessionId, tenantDomain);

                    for (Map.Entry<String, Map<String, AuthenticatedIdPData>> application :
                            sessionContext.getAuthenticatedIdPsOfApp().entrySet()) {
                        applications.add(new Application(
                                null,
                                application.getKey()));
                    }
                }
            }
        }
        String initiatorType = null;

        Flow flow = params.containsKey("flow") ? (Flow) params.get("flow") : null;
        if (flow != null) {
            switch (flow.getInitiatingPersona()) {
                case ADMIN:
                    initiatorType = "admin";
                    break;
                case USER:
                    initiatorType = "user";
                    break;
                case APPLICATION:
                    initiatorType = "application";
                    break;
                case SYSTEM:
                    initiatorType = "system";
                    break;
            }
        }
        if (sessionData instanceof String) {
            return new WSO2SessionRevokedEventPayload.Builder()
                    .sessionId((String) sessionData)
                    .user(user)
                    .tenant(tenant)
                    .userResidentOrganization(b2bUserResidentOrganization)
                    .sessionId(sessionData.toString())
                    .userStore(userStore)
                    .initiatorType(initiatorType)
                    .applications(applications)
                    .build();
        }
        return new WSO2SessionRevokedEventPayload.Builder()
                .user(user)
                .tenant(tenant)
                .userResidentOrganization(b2bUserResidentOrganization)
                .userStore(userStore)
                .initiatorType(initiatorType)
                .applications(applications)
                .build();
    }

    @Override
    public EventPayload buildSessionCreateEvent(EventData eventData) throws IdentityEventException {
        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        SessionContext sessionContext = eventData.getSessionContext();

        if (authenticatedUser == null) {
            throw new IdentityEventException("Authenticated user cannot be null.");
        }

        if (sessionContext == null) {
            throw new IdentityEventException("Session context cannot be null.");
        }

        User user = new User();
        WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);

        Organization tenant = new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain())),
                authenticationContext.getTenantDomain());
        UserStore userStore = null;
        if (authenticatedUser.getUserStoreDomain() != null) {
            userStore = new UserStore(authenticatedUser.getUserStoreDomain());
        }
        Organization b2bUserResidentOrganization = null;
        if (authenticatedUser.getUserResidentOrganization() != null) {
            b2bUserResidentOrganization = getUserResidentOrganization(
                    authenticatedUser.getUserResidentOrganization());
        }

        String sessionId = extractSessionId(eventData);

        List<Application> applications = new ArrayList<>();

        for (Map.Entry<String, Map<String, AuthenticatedIdPData>> application :
                sessionContext.getAuthenticatedIdPsOfApp().entrySet()) {
            applications.add(new Application(
                    null,
                    application.getKey()));
        }

        return new WSO2SessionCreatedEventPayload.Builder()
                .sessionId(sessionId)
                .currentAcr(authenticationContext.getSelectedAcr())
                .user(user)
                .tenant(tenant)
                .userResidentOrganization(b2bUserResidentOrganization)
                .userStore(userStore)
                .applications(applications)
                .build();
    }

    @Override
    public EventPayload buildSessionUpdateEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventPayload buildSessionExpireEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventPayload buildSessionExtendEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventSchema getEventSchemaType() {

        return EventSchema.WSO2;
    }

    protected SessionContext getSessionContextFromSessionId(String sessionId, String tenantDomain) {
        return FrameworkUtils.getSessionContextFromCache(sessionId, tenantDomain);
    }
}
