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
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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
        List<UserSession> sessions;
        try {
            sessions = params.containsKey("sessions") ?
                    (List<UserSession>) params.get("sessions") : null;
            if (sessions != null) {
                for (UserSession session : sessions) {
                    for (org.wso2.carbon.identity.application.authentication.framework.model.Application
                            sessionApplication : session.getApplications()) {
                        Application application = new Application(sessionApplication.getAppName(),
                                sessionApplication.getAppId());
                        applications.add(application);
                    }
                }
            } else {
                log.debug("Sessions list is null.");
            }
        } catch (ClassCastException e) {
            log.error("Error while casting sessions to List<UserSession>", e);
            throw new IdentityEventException("Error while casting sessions to List<UserSession>", e);
        }

        String initiatorType = null;

        Flow flow = eventData.getFlow();
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
        if (sessions != null && sessions.size() == 1) {
            return new WSO2SessionRevokedEventPayload.Builder()
                    .user(user)
                    .tenant(tenant)
                    .organization(b2bUserResidentOrganization)
                    .sessionId(sessions.get(0).getSessionId())
                    .userStore(userStore)
                    .initiatorType(initiatorType)
                    .applications(applications)
                    .build();
        }
        return new WSO2SessionRevokedEventPayload.Builder()
                .user(user)
                .tenant(tenant)
                .organization(b2bUserResidentOrganization)
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

        String sessionId;

        Map<String, Object> params = eventData.getEventParams();
        if (params.containsKey(Constants.EventDataProperties.SESSION_ID) &&
                params.get(Constants.EventDataProperties.SESSION_ID) != null) {
            sessionId =  params.get(Constants.EventDataProperties.SESSION_ID).toString();
        } else {
            sessionId = authenticationContext.getSessionIdentifier();
        }

        List<Application> applications = new ArrayList<>();
        List<org.wso2.carbon.identity.application.authentication.framework.model.Application> sessionApplications =
                params.containsKey("applications") ?
                        (List<org.wso2.carbon.identity.application.authentication.framework.model.Application>)
                        params.get("applications") : Collections.emptyList();
        for (org.wso2.carbon.identity.application.authentication.framework.model.Application sessionApplication :
                sessionApplications) {
            Application application = new Application(
                    sessionApplication.getAppId(),
                    sessionApplication.getAppName());
            applications.add(application);
        }

        return new WSO2SessionCreatedEventPayload.Builder()
                .sessionId(sessionId)
                .currentAcr(authenticationContext.getSelectedAcr())
                .user(user)
                .tenant(tenant)
                .organization(b2bUserResidentOrganization)
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
    public org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema getEventSchemaType() {

        return org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
    }
}
