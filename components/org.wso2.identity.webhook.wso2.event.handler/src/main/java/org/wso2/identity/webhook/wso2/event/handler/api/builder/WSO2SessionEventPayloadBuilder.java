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
import org.wso2.carbon.identity.application.authentication.framework.exception.session.mgt.SessionManagementException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Session;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class WSO2SessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2SessionEventPayloadBuilder.class);

    @Override
    public EventPayload buildSessionTerminateEvent(EventData eventData) throws IdentityEventException {

        User user = buildUser(eventData);
        Organization tenant = buildTenant(eventData);
        UserStore userStore = buildUserStore(eventData);
        List<Session> sessions = getSessions(eventData);

        return new WSO2SessionRevokedEventPayload.Builder()
                .user(user)
                .tenant(tenant)
                .userStore(userStore)
                .sessions(sessions)
                .build();
    }

    @Override
    public EventPayload buildSessionCreateEvent(EventData eventData) throws IdentityEventException {

        validateEventData(eventData);

        User user = buildUser(eventData);
        Organization tenant = buildTenant(eventData);
        UserStore userStore = buildUserStore(eventData);
        String sessionId = getSessionId(eventData);
        Application application = buildApplication(eventData.getAuthenticationContext());

        return new WSO2SessionCreatedEventPayload.Builder()
                .sessionId(sessionId)
                .currentAcr(eventData.getAuthenticationContext().getSelectedAcr())
                .user(user)
                .tenant(tenant)
                .userStore(userStore)
                .application(application)
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

    private void validateEventData(EventData eventData) throws IdentityEventException {

        if (eventData.getAuthenticatedUser() == null || eventData.getAuthenticationContext() == null) {
            throw new IdentityEventException(
                    "Authenticated user or authentication context cannot be null in event data.");
        }
    }

    private User buildUser(EventData eventData) {

        User user = null;
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        if (authenticatedUser != null) {
            user = new User();
            WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);
            WSO2PayloadUtils.populateUserClaims(user, authenticatedUser, eventData.getTenantDomain());
        } else if (eventData.getUserId() != null) {
            user = new User();
            String userId = eventData.getUserId();
            WSO2PayloadUtils.populateUserIdAndRef(user, userId);
            WSO2PayloadUtils.populateUserClaims(user, userId, eventData.getTenantDomain());
        }

        return user;
    }

    private Organization buildTenant(EventData eventData) {

        String tenantDomain = eventData.getTenantDomain();
        return new Organization(String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain)), tenantDomain);
    }

    private UserStore buildUserStore(EventData eventData) {

        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        if (authenticatedUser != null && authenticatedUser.getUserStoreDomain() != null) {
            return new UserStore(authenticatedUser.getUserStoreDomain());
        }
        return null;
    }

    private String getSessionId(EventData eventData) {

        Map<String, Object> params = eventData.getEventParams();
        if (params.containsKey(Constants.EventDataProperties.SESSION_ID) &&
                params.get(Constants.EventDataProperties.SESSION_ID) != null) {
            return params.get(Constants.EventDataProperties.SESSION_ID).toString();
        }
        return eventData.getAuthenticationContext().getSessionIdentifier();
    }

    private List<Session> getSessions(EventData eventData) throws IdentityEventException {

        Map<String, Object> params = eventData.getEventParams();
        if (params.containsKey(Constants.EventDataProperties.SESSION_ID)) {
            String sessionId = params.get(Constants.EventDataProperties.SESSION_ID).toString();
            return retrieveSessionsById(sessionId);
        } else if (params.containsKey(IdentityEventConstants.EventProperty.SESSION_IDS)) {
            List<String> sessionIds = params.get(IdentityEventConstants.EventProperty.SESSION_IDS) instanceof List ?
                    (List<String>) params.get(IdentityEventConstants.EventProperty.SESSION_IDS) : null;
            if (sessionIds == null || sessionIds.isEmpty()) {
                LOG.debug("Session IDs are not provided in the event data.");
                return new ArrayList<>();
            }
            return retrieveSessionsByIds(sessionIds);
        }
        return new ArrayList<>();
    }

    private List<Session> retrieveSessionsById(String sessionId) throws IdentityEventException {

        try {
            Optional<UserSession> userSession = WSO2EventHookHandlerDataHolder.getInstance()
                    .getUserSessionManagementService().getUserSessionBySessionId(sessionId);
            return userSession.map(this::buildSessionList).orElseGet(ArrayList::new);
        } catch (SessionManagementException e) {
            throw new IdentityEventException(
                    "Error while retrieving session information from User Session Management Service", e);
        }
    }

    private List<Session> retrieveSessionsByIds(List<String> sessionIds) throws IdentityEventException {

        List<Session> sessions = new ArrayList<>();
        // todo: This call retrieves session data per session and can be optimized to retrieve all sessions
        //  in a single call. However, the UserSessionManagementService currently does not provide a method
        //  to retrieve multiple sessions by IDs. Should evaluate impact and optimize accordingly.
        for (String sessionId : sessionIds) {
            sessions.addAll(retrieveSessionsById(sessionId));
        }
        return sessions;
    }

    private List<Session> buildSessionList(UserSession userSession) {

        List<Session> sessions = new ArrayList<>();
        List<Application> applications = new ArrayList<>();
        userSession.getApplications().forEach(app -> {
            Application application = new Application(app.getAppName(), app.getAppId());
            applications.add(application);
        });
        Session sessionModel = new Session(userSession.getSessionId(), applications);
        sessions.add(sessionModel);
        return sessions;
    }

    private Application buildApplication(AuthenticationContext authenticationContext) {

        return new Application(
                authenticationContext.getServiceProviderResourceId(),
                authenticationContext.getServiceProviderName());
    }
}
