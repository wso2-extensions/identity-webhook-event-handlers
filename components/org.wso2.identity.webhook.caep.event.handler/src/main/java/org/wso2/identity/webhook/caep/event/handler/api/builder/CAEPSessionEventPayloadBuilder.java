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
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionEstablishedEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionPresentedEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionRevokedEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is responsible for building CAEP session event payloads.
 */
public class CAEPSessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(CAEPSessionEventPayloadBuilder.class);

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
        Map<String, String> reasonAdmin = new HashMap<>();
        Map<String, String> reasonUser = new HashMap<>();

        Flow flow = eventData.getFlow();
        if (flow != null) {
            // TODO: Switch these with relevant flow names
            switch (flow.getInitiatingPersona()) {
                case USER:
                    initiatingEntity = "user";
                    break;
                case ADMIN:
                    initiatingEntity = "admin";
                    break;
                // Due to CAEP definitions, "SYSTEM" initiatingPersona corresponds to "policy" initiatingEntity Value
                case APPLICATION:
                    initiatingEntity = "system";
                    break;
                case SYSTEM:
                    initiatingEntity = "policy";
                    break;
            }
            // TODO: Define Flows and change names accordingly
            switch (flow.getName()) {
                case LOGOUT:
                    reasonAdmin.put("en", "User Logout");
                    reasonUser.put("en", "User Logged Out");
                    break;
                case DELETE_USER:
                    reasonAdmin.put("en", "User Deleted");
                    reasonUser.put("en", "User Deleted");
                    initiatingEntity = "policy";
                    break;
                case ACCOUNT_DISABLE:
                    reasonAdmin.put("en", "Account Disabled");
                    reasonUser.put("en", "User Account was Disabled");
                    initiatingEntity = "policy";
                    break;
                case ACCOUNT_LOCK:
                    reasonAdmin.put("en", "Account Locked");
                    reasonUser.put("en", "User Account was Locked");
                    initiatingEntity = "policy";
                    break;
                case SESSION_REVOKE:
                    if (flow.getInitiatingPersona() == Flow.InitiatingPersona.ADMIN) {
                        reasonAdmin.put("en", "Session Revoked by Admin");
                        reasonUser.put("en", "Session Revoked by Admin");
                    } else if (flow.getInitiatingPersona() == Flow.InitiatingPersona.USER) {
                        reasonAdmin.put("en", "Session Revoked by User");
                        reasonUser.put("en", "Session Revoked by User");
                    }
            }
        }

        return new CAEPSessionRevokedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser.isEmpty() ? null : reasonUser)
                .reasonAdmin(reasonAdmin.isEmpty() ? null : reasonAdmin)
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

        String initiatingEntity = "user";

        Map<String, String> reasonAdmin = new HashMap<>();
        reasonAdmin.put("en", "Initial Login");
        Map<String, String> reasonUser = new HashMap<>();
        reasonUser.put("en", "User Logged In");

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

        return new CAEPSessionEstablishedEventPayload.Builder()
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
        // TODO: Set these values according to the flow
        String initiatingEntity = null;
        Map<String, String> reasonAdmin = null;
        Map<String, String> reasonUser = null;

        // TODO: Add ips
        List<String> ips = null;

        // TODO: Add FpUa
        String fpUa = null;

        // TODO: Add ExtId
        String extId = null;

        return new CAEPSessionPresentedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonUser(reasonUser)
                .reasonAdmin(reasonAdmin)
                .ips(ips)
                .fpUa(fpUa)
                .extId(extId)
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
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.CAEP;
    }
}
