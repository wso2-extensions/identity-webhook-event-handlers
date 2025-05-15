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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.event.common.publisher.model.common.Subject;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.SESSION_CREATE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.SESSION_EXPIRE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.SESSION_EXTEND;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.SESSION_UPDATE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.USER_SESSION_TERMINATE;

/**
 * This class handles session events and publishes them to the configured event publisher.
 */
public class SessionEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(SessionEventHookHandler.class);
    private final EventConfigManager eventConfigManager;

    public SessionEventHookHandler(EventConfigManager eventConfigManager) {

        this.eventConfigManager = eventConfigManager;
    }

    @Override
    public String getName() {

        return Constants.SESSION_EVENT_HOOK_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        for (EventSchema schema : EventSchema.values()) {
            SessionEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getSessionEventPayloadBuilder(schema);

            if (payloadBuilder == null) {
                log.debug("Session event payload builder not found for schema: " + schema);
                continue;
            }

            EventPublisherConfig sessionEventPublisherConfig;

            try {
                sessionEventPublisherConfig = EventHookHandlerUtils.getEventPublisherConfigForTenant((String)
                                eventData.getSessionContext().getProperty("tenantDomain"),
                        event.getEventName(), eventConfigManager);

                EventPayload eventPayload = null;
                String eventUri = null;

                if (sessionEventPublisherConfig.isPublishEnabled()) {
                    switch (IdentityEventConstants.EventName.valueOf(event.getEventName())) {
                        case USER_SESSION_TERMINATE:
                            eventPayload = payloadBuilder.buildSessionTerminateEvent(eventData);
                            eventUri = eventConfigManager.getEventUri(
                                    EventHookHandlerUtils.resolveEventHandlerKey(schema, USER_SESSION_TERMINATE));
                            break;
                        case SESSION_EXPIRE:
                            eventPayload = payloadBuilder.buildSessionExpireEvent(eventData);
                            eventUri = eventConfigManager.getEventUri(
                                    EventHookHandlerUtils.resolveEventHandlerKey(schema, SESSION_EXPIRE));
                            break;
                        case SESSION_CREATE:
                            eventPayload = payloadBuilder.buildSessionCreateEvent(eventData);
                            eventUri = eventConfigManager.getEventUri(
                                    EventHookHandlerUtils.resolveEventHandlerKey(schema, SESSION_CREATE));
                            break;
                        case SESSION_UPDATE:
                            eventPayload = payloadBuilder.buildSessionUpdateEvent(eventData);
                            eventUri = eventConfigManager.getEventUri(
                                    EventHookHandlerUtils.resolveEventHandlerKey(schema, SESSION_UPDATE));
                            break;

                        case SESSION_EXTEND:
                            eventPayload = payloadBuilder.buildSessionExtendEvent(eventData);
                            eventUri = eventConfigManager.getEventUri(
                                    EventHookHandlerUtils.resolveEventHandlerKey(schema, SESSION_EXTEND));
                            break;
                    }
                    if (eventPayload != null) {
                        Subject subject = null;
                        if (schema.equals(EventSchema.CAEP)) {
                            subject = EventHookHandlerUtils.extractSubjectFromEventData(eventData);
                        }
                        String tenantDomain = eventData.getAuthenticatedUser().getTenantDomain();

                        SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils.
                                buildSecurityEventToken(eventPayload, eventUri, subject);
                        EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
                    }
                }
            } catch (IdentityEventException e) {
                log.debug("Error while retrieving event publisher configuration for tenant.", e);
            }
        }
    }
}
