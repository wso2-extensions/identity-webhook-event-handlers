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

package org.wso2.identity.webhook.caep.event.handler.api.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.event.common.publisher.model.common.ComplexSubject;
import org.wso2.identity.event.common.publisher.model.common.SimpleSubject;
import org.wso2.identity.event.common.publisher.model.common.Subject;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.SecurityEventTokenBuilder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils.constructBaseURL;
import static org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils.getCorrelationID;

public class CAEPSecurityEventTokenBuilder implements SecurityEventTokenBuilder {

    @Override
    public SecurityEventTokenPayload buildSecurityEventTokenPayload(
            EventPayload eventPayload, String eventUri, EventData eventData) throws IdentityEventException {

        if (eventPayload == null) {
            throw new IdentityEventException("Invalid event payload input: Event payload input cannot be null.");
        }

        if (StringUtils.isEmpty(eventUri)) {
            throw new IdentityEventException("Invalid event URI input: Event URI input cannot be null or empty.");
        }

        if (eventData == null) {
            throw new IdentityEventException("Invalid event data input: Event data input cannot be null.");
        }

        Subject subject;
        if (eventData.getEventName().equals(IdentityEventConstants.EventName.VERIFICATION.name())) {
            subject = buildVerificationSubject(eventData);
        } else {
            subject = extractSubjectFromEventData(eventData);
        }


        Map<String, EventPayload> eventMap = new HashMap<>();
        eventMap.put(eventUri, eventPayload);

        // TODO : Add the audience to the event payload.
        return new SecurityEventTokenPayload.CAEPBuilder()
                .iss(constructBaseURL())
                .iat(System.currentTimeMillis())
                .jti(UUID.randomUUID().toString())
                .rci(getCorrelationID())
                .events(eventMap)
                .subId(subject)
                .build();
    }

    @Override
    public EventSchema getEventSchema() {

        return EventSchema.CAEP;
    }

    /**
     * Extracts the subject from the event data.
     *
     * @param eventData Event data.
     * @return Subject.
     * @throws IdentityEventException If an error occurs while extracting the subject.
     */
    public static Subject extractSubjectFromEventData(EventData eventData) throws IdentityEventException {

        AuthenticatedUser authenticatedUser = extractAuthenticatedUser(eventData);
        String sessionId = extractSessionId(eventData);
        SimpleSubject user;
        try {
            user = SimpleSubject.createOpaqueSubject(authenticatedUser.getUserId());
        } catch (UserIdNotFoundException e) {
            throw new IdentityEventException("Error occurred while retrieving user id", e);
        }
        SimpleSubject tenant = SimpleSubject.createOpaqueSubject(String.valueOf(
                IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain())));
        SimpleSubject session = SimpleSubject.createOpaqueSubject(sessionId);

        return ComplexSubject.builder()
                .tenant(tenant)
                .user(user)
                .session(session)
                .build();
    }

    /**
     *
     */
    private static Subject buildVerificationSubject(EventData eventData) throws IdentityEventException {

        Map<String, Object> params = eventData.getEventParams();
        String streamId = params.containsKey(Constants.EventDataProperties.STREAM_ID) ?
                params.get(Constants.EventDataProperties.STREAM_ID).toString() : null;
        if (streamId == null) {
            throw new IdentityEventException("Stream ID cannot be null");
        }

        return SimpleSubject.createOpaqueSubject(streamId);
    }

    /**
     * Extracts the authenticated user from the event data.
     *
     * @param eventData Event data.
     * @return Authenticated user.
     * @throws IdentityEventException If an error occurs while extracting the authenticated user.
     */
    private static AuthenticatedUser extractAuthenticatedUser(EventData eventData) throws IdentityEventException {

        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        try {
            if (authenticatedUser == null) {
                authenticatedUser = (AuthenticatedUser) eventData.getEventParams().
                        get(Constants.EventDataProperties.USER);
            }
            return authenticatedUser;
        } catch (ClassCastException e) {
            throw new IdentityEventException("Error occurred while retrieving authenticated user", e);
        }
    }

    /**
     * Extracts the session ID from the event data.
     *
     * @param eventData Event data.
     * @return Session ID.
     * @throws IdentityEventException If an error occurs while extracting the session ID.
     */
    public static String extractSessionId(EventData eventData) {

        Map<String, Object> params = eventData.getEventParams();
        // For Session Terminate Events, only extract sessionId if a single session is terminated
        if (eventData.getEventName().equals(IdentityEventConstants.EventName.USER_SESSION_TERMINATE.name())) {
            List<UserSession> sessions = params.containsKey(Constants.EventDataProperties.SESSIONS) ?
                    (List<UserSession>) params.get(Constants.EventDataProperties.SESSIONS) : null;
            if (sessions != null) {
                if (sessions.size() == 1) {
                    return sessions.get(0).getSessionId();
                } else {
                    return null;
                }
            }
        }
        if (eventData.getEventParams().containsKey(Constants.EventDataProperties.SESSION_ID) &&
                eventData.getEventParams().get(Constants.EventDataProperties.SESSION_ID) != null) {
            return eventData.getEventParams().get(Constants.EventDataProperties.SESSION_ID).toString();
        } else if (eventData.getAuthenticationContext() != null) {
            return eventData.getAuthenticationContext().getSessionIdentifier();
        }
        return null;
    }
}
