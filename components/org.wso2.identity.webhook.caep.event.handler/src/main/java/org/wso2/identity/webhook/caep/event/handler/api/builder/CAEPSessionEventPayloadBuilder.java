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
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionEstablishedAndPresentedEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionRevokedEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is responsible for building CAEP session event payloads.
 */
public class CAEPSessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(CAEPSessionEventPayloadBuilder.class);

    static final String IS_INITIAL_LOGIN = "isInitialLogin";
    static final String CREATED_TIMESTAMP = "CreatedTimestamp";
    static final String UPDATED_TIMESTAMP = "UpdatedTimestamp";
    static final String EVENT_TIMESTAMP = "eventTimestamp";

    private long extractEventTimeStamp(Map<String, Object> params) {

        return params.containsKey(EVENT_TIMESTAMP) ?
                Long.parseLong(params.get(EVENT_TIMESTAMP).toString()) :
                System.currentTimeMillis();

    }

    @Override
    public EventPayload buildSessionTerminateEvent(EventData eventData) throws IdentityEventException {

        final Map<String, Object> params = eventData.getEventParams();
        long eventTimeStamp = extractEventTimeStamp(params);
        String initiatingEntity = null;
        Map<String, String> reasonAdmin = null;
        Map<String, String> reasonUser = null;

        if (eventData.getAuthenticationContext() == null) {
            throw new IdentityEventException("Authentication context cannot be null");
        }

        try {
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
        Long eventTimeStamp = null;
        if (sessionContext != null && sessionContext.getProperty(CREATED_TIMESTAMP) != null) {
            eventTimeStamp = Long.parseLong(sessionContext.getProperty(CREATED_TIMESTAMP).toString());
        }

        if (eventTimeStamp == null) {
            eventTimeStamp = extractEventTimeStamp(params);
        }

        String initiatingEntity = null;
        Map<String, String> reasonAdmin = null;
        Map<String, String> reasonUser = null;

        AuthenticationContext context = eventData.getAuthenticationContext();
        if (context != null) {
            // If Initial Login
            if (context.getParameter(IS_INITIAL_LOGIN) != null &&
                    context.getParameter(IS_INITIAL_LOGIN).toString().equalsIgnoreCase("true")) {
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

        // TODO: Add Acr
        String acr = context.getSelectedAcr();

        return new CAEPSessionEstablishedAndPresentedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser)
                .reasonAdmin(reasonAdmin)
                .amr(amr)
                .ips(ips)
                .fpUa(fpUa)
                .extId(extId)
                .acr(acr)
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

        final Map<String, Object> params = eventData.getEventParams();
        SessionContext sessionContext = eventData.getSessionContext();
        Long eventTimeStamp = null;
        if (sessionContext != null && sessionContext.getProperty(UPDATED_TIMESTAMP) != null) {
            eventTimeStamp = Long.parseLong(sessionContext.getProperty(UPDATED_TIMESTAMP).toString());
        }

        if (eventTimeStamp == null) {
            eventTimeStamp = extractEventTimeStamp(params);
        }
        String initiatingEntity = null;
        Map<String, String> reasonAdmin = null;
        Map<String, String> reasonUser = null;

        // TODO: Add AMR list Support
        List<String> amr = null;

        // TODO: Add ips
        List<String> ips = null;

        // TODO: Add FpUa
        String fpUa = null;

        // TODO: Add ExtId
        String extId = null;

        // TODO: Add Acr
        String acr = eventData.getAuthenticationContext() != null ?
                eventData.getAuthenticationContext().getSelectedAcr() : null;

        return new CAEPSessionEstablishedAndPresentedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser)
                .reasonAdmin(reasonAdmin)
                .amr(amr)
                .ips(ips)
                .fpUa(fpUa)
                .extId(extId)
                .acr(acr)
                .build();
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
