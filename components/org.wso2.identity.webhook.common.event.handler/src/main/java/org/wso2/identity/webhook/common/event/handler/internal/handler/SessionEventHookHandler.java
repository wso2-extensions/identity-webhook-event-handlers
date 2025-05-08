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
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.SESSION_TERMINATE;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventName.SESSION_UPDATE;

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

        // TODO: Get the schema type from tenant configuration
        EventSchema schema = EventSchema.CAEP;
        SessionEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getSessionEventPayloadBuilder(schema);

        EventPublisherConfig sessionEventPublisherConfig;

        try {
            String tenantDomain = eventData.getAuthenticatedUser().getTenantDomain();
            sessionEventPublisherConfig = EventHookHandlerUtils.getEventPublisherConfigForTenant((String)
                            tenantDomain,
                    event.getEventName(), eventConfigManager);

            EventPayload eventPayload = null;

            if (sessionEventPublisherConfig.isPublishEnabled()) {
                String eventUri = eventConfigManager.getEventUri(
                        EventHookHandlerUtils.resolveEventHandlerKey(schema,
                                IdentityEventConstants.EventName.valueOf(event.getEventName())));
                switch (IdentityEventConstants.EventName.valueOf(event.getEventName())) {
                    case SESSION_TERMINATE:
                        eventPayload = payloadBuilder.buildSessionTerminateEvent(eventData);
                        break;
                    case SESSION_EXPIRE:
                        eventPayload = payloadBuilder.buildSessionExpireEvent(eventData);
                        break;
                    case SESSION_CREATE:
                        eventPayload = payloadBuilder.buildSessionCreateEvent(eventData);
                        break;
                    case SESSION_UPDATE:
                        eventPayload = payloadBuilder.buildSessionUpdateEvent(eventData);
                        break;
                    case SESSION_EXTEND:
                        eventPayload = payloadBuilder.buildSessionExtendEvent(eventData);
                        break;
                }
                Subject subject = null;
                if (schema.equals(EventSchema.CAEP)) {
                    subject = EventHookHandlerUtils.extractSubjectFromEventData(eventData);
                }

                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils.
                        buildSecurityEventToken(eventPayload, eventUri, subject);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            }

        } catch (IdentityEventException e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }
    }
}
