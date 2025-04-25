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
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

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

//    @Override
//    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {
//        IdentityEventMessageContext identityContext = (IdentityEventMessageContext) messageContext;
//        String eventName = identityContext.getEvent().getEventName();
//        boolean canHandle = super.canHandle()
//        if (canHandle) {
//            log.debug(eventName + " event can be handled by CAEP Session Event Handler");
//        } else {
//            log.debug(eventName + " event cannot be handled by CAEP Session Event Handler");
//        }
//        return canHandle;
//    }
//
//    private boolean isSupportedEvent(String eventName) {
//        return (eventName.equals(IdentityEventConstants.EventName.SESSION_TERMINATE.name()) ||
//                eventName.equals(IdentityEventConstants.EventName.SESSION_EXPIRE.name()) ||
//                eventName.equals(IdentityEventConstants.EventName.SESSION_CREATE.name()) ||
//                eventName.equals(IdentityEventConstants.EventName.SESSION_UPDATE.name()) ||
//                eventName.equals(IdentityEventConstants.EventName.SESSION_EXTEND.name()));
//    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

//        if (eventData.getAuthenticationContext().isPassiveAuthenticate()) {
//            return;
//        }
        // TODO: Get the schema type from tenant configuration
        String schema = Constants.CAEP_EVENT_SCHEMA;
        SessionEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getSessionEventPayloadBuilder(schema);

        EventPublisherConfig sessionEventPublisherConfig;

        try {
            sessionEventPublisherConfig = EventHookHandlerUtils.getEventPublisherConfigForTenant(
                    (String) eventData.getSessionContext().getProperty("tenantDomain"),
                    event.getEventName(), eventConfigManager);

            EventPayload eventPayload = null;
            String eventUri = null;

            if (sessionEventPublisherConfig.isPublishEnabled()) {
                if (IdentityEventConstants.EventName.SESSION_TERMINATE.name().equals(event.getEventName())) {
                    eventPayload = payloadBuilder.buildSessionTerminateEvent(eventData);
                    eventUri = eventConfigManager.getEventUri(EventHookHandlerUtils.
                            resolveEventHandlerKey(schema, IdentityEventConstants.EventName.SESSION_TERMINATE));
                } else if (IdentityEventConstants.EventName.SESSION_EXPIRE.name().equals(event.getEventName())) {
                    eventPayload = payloadBuilder.buildSessionExpireEvent(eventData);
                    eventUri = eventConfigManager.getEventUri(EventHookHandlerUtils.
                            resolveEventHandlerKey(schema, IdentityEventConstants.EventName.SESSION_EXPIRE));
                } else if (IdentityEventConstants.EventName.SESSION_CREATE.name().equals(event.getEventName())) {
                    eventPayload = payloadBuilder.buildSessionCreateEvent(eventData);
                    eventUri = eventConfigManager.getEventUri(EventHookHandlerUtils.
                            resolveEventHandlerKey(schema, IdentityEventConstants.EventName.SESSION_CREATE));
                } else if (IdentityEventConstants.EventName.SESSION_UPDATE.name().equals(event.getEventName())) {
                    eventPayload = payloadBuilder.buildSessionUpdateEvent(eventData);
                    eventUri = eventConfigManager.getEventUri(EventHookHandlerUtils.
                            resolveEventHandlerKey(schema, IdentityEventConstants.EventName.SESSION_UPDATE));
                } else if (IdentityEventConstants.EventName.SESSION_EXTEND.name().equals(event.getEventName())) {
                    eventPayload = payloadBuilder.buildSessionExtendEvent(eventData);
                    eventUri = eventConfigManager.getEventUri(EventHookHandlerUtils.
                            resolveEventHandlerKey(schema, IdentityEventConstants.EventName.SESSION_EXTEND));
                }
                String tenantDomain = eventData.getAuthenticatedUser().getTenantDomain();
                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            }


        } catch (IdentityEventException e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }


    }



}
