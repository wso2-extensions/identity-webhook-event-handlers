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

package org.wso2.identity.webhook.caep.event.handler.api.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.constants.Constants;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionEstablishedAndPresentedEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionRevokedEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CAEPSessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(CAEPSessionEventPayloadBuilder.class);

    private long extractEventTimeStamp(Map<String, Object> params) {

        return params.containsKey(Constants.CAEPMapParams.EVENT_TIME_STAMP) ?
                Long.parseLong(params.get(Constants.CAEPMapParams.EVENT_TIME_STAMP).toString()) :
                System.currentTimeMillis();

    }

    @Override
    public EventPayload buildSessionTerminateEvent(EventData eventData) throws IdentityEventException {
        final Map<String, Object> params = eventData.getEventParams();
        long eventTimeStamp = extractEventTimeStamp(params);
        String initiatingEntity = null;
        Map<String, String> reasonAdmin = null;
        Map<String, String> reasonUser = null;


        try {
            // If logout
            if (eventData.getAuthenticationContext().isLogoutRequest()) {
                initiatingEntity = "user";
                reasonAdmin = new HashMap<>();
                reasonAdmin.put("en", "User logout");
                reasonUser = new HashMap<>();
                reasonUser.put("en", "User Logged out");

            }

        } catch (Exception e) {
            throw new IdentityEventException("Error occurred while retrieving Request user", e);
        }

        return new CAEPSessionRevokedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser)
                .reasonAdmin(reasonAdmin)
                .build();
    }

    /**
     * Build the Session Create event.
     *
     * @param eventData Event data.
     * @return Event payload.
     */
    @Override
    public EventPayload buildSessionCreateEvent(EventData eventData) throws IdentityEventException {

        SessionContext sessionContext = eventData.getSessionContext();
        final Map<String, Object> params = eventData.getEventParams();
        long eventTimeStamp;
        try {
            Long createdTimestamp = (Long) sessionContext.getProperty("CreatedTimestamp");
            if (createdTimestamp == null) {
                eventTimeStamp = extractEventTimeStamp(params);
            } else {
                eventTimeStamp = createdTimestamp;
            }
        } catch (ClassCastException e) {
            log.error("Error occurred while retrieving Created Timestamp", e);
            eventTimeStamp = extractEventTimeStamp(params);
        }

        String initiatingEntity = null;
        Map<String, String> reasonAdmin = null;
        Map<String, String> reasonUser = null;

        AuthenticationContext context = eventData.getAuthenticationContext();
        if (context != null) {
            // If Initial Login
            if (context.getParameter("isInitialLogin").toString().equalsIgnoreCase("true")) {
                reasonAdmin = new HashMap<>();
                reasonAdmin.put("en", "Initial Login");
                reasonUser = new HashMap<>();
                reasonUser.put("en", "User Logged In");
                initiatingEntity = "user";
            }
        }

        // TODO: Add AMR list Support
        List<String> amr = null;

        // TODO: Add ips
        List<String> ips = null;

        // TODO: Add FpUa
        String fpUa = null;

        // TODO: Add ExtId
        String extId = null;

        return new CAEPSessionEstablishedAndPresentedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser)
                .reasonAdmin(reasonAdmin)
                .amr(amr)
                .ips(ips)
                .fpUa(fpUa)
                .extId(extId)
                .build();
    }

    /**
     * Build the Session Update event.
     *
     * @param eventData Event data.
     * @return Event payload.
     */
    @Override
    public EventPayload buildSessionUpdateEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    /**
     * Build the Session Expire event.
     *
     * @param eventData Event data.
     * @return Event payload.
     */
    @Override
    public EventPayload buildSessionExpireEvent(EventData eventData) throws IdentityEventException {
            return null;
//        final Map<String, Object> params = eventData.getEventParams();
//        long eventTimeStamp = extractEventTimeStamp(params);
//        String initiatingEntity = "system";
//        Map<String, String> reasonAdmin = new HashMap<>();
//        reasonAdmin.put("en", "Session Expired");
//        Map<String, String> reasonUser = new HashMap<>();
//        reasonUser.put("en", "User Session Expired due to inactivity");
//
//        AuthenticatedUser authenticatedUser = extractAuthenticatedUser(eventData);
//        String sessionId = extractSessionId(eventData, params);
//
//        if (authenticatedUser == null || sessionId == null) {
//            log.debug("No Authenticated User or Session ID found");
//            throw new IdentityEventException("Authenticated User or Session ID cannot be null");
//        }
//
//        Subject subject = new ComplexSubject();
//        try {
//            subject.addProperty("user", SimpleSubject.createOpaqueSubject(authenticatedUser.getUserId()));
//        } catch (UserIdNotFoundException e) {
//            throw new IdentityEventException("Error occurred while retrieving user id", e);
//        }
//        subject.addProperty("tenant", SimpleSubject.createOpaqueSubject(String.valueOf(
//                IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain()))));
//        subject.addProperty("session", SimpleSubject.createOpaqueSubject(sessionId));
//
//        return new CAEPSessionRevokedEventPayload.Builder()
//                .eventTimeStamp(eventTimeStamp)
//                .initiatingEntity(initiatingEntity)
//                .reasonUser(reasonUser)
//                .reasonAdmin(reasonAdmin)
//                .subject(subject)
//                .build();
    }

    /**
     * Build the Session Extend event.
     *
     * @param eventData Event data.
     * @return Event payload.
     */
    @Override
    public EventPayload buildSessionExtendEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventSchema getEventSchemaType() {

        return EventSchema.CAEP;
    }
}
