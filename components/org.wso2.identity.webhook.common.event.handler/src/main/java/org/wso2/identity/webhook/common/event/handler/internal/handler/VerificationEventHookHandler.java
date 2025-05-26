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
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.VerificationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.SecurityEventTokenBuilder;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;
import org.wso2.identity.webhook.common.event.handler.internal.util.SecurityEventTokenBuilderFactory;

/**
 * This class is responsible for handling verification events.
 */
public class VerificationEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(VerificationEventHookHandler.class);

    private final EventConfigManager eventConfigManager;

    public VerificationEventHookHandler(EventConfigManager eventConfigManager) {

        this.eventConfigManager = eventConfigManager;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        IdentityEventMessageContext identityContext = (IdentityEventMessageContext) messageContext;
        String eventName = identityContext.getEvent().getEventName();

        boolean canHandle = isSupportedEvent(eventName);
        if (canHandle) {
            log.debug(eventName + " event can be handled.");
        } else {
            log.debug(eventName + " event cannot be handled.");
        }
        return canHandle;
    }

    @Override
    public String getName() {

        return Constants.VERIFICATION_EVENT_HOOK_NAME;
    }

    private boolean isSupportedEvent(String eventName) {

        return eventName.equals(IdentityEventConstants.EventName.VERIFICATION.name());
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        EventSchema schema = EventSchema.CAEP;
        VerificationEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getVerificationEventPayloadBuilder(schema);

        // TODO: Change this when the event schema type is added to the tenant configuration.
        if (payloadBuilder == null) {
            throw new IdentityEventException("Login event payload builder not found for schema: " + schema);
        }

        SecurityEventTokenBuilder securityEventTokenBuilder = SecurityEventTokenBuilderFactory
                .getSecurityEventTokenBuilder(schema);

        if (securityEventTokenBuilder == null) {
            log.debug("Security event token builder not found for schema: " + schema);
            return;
        }

        EventPublisherConfig eventPublisherConfig;
        EventPayload eventPayload;

        try {
            String tenantDomain = eventData.getAuthenticationContext().getTenantDomain();
            eventPublisherConfig = EventHookHandlerUtils.getEventPublisherConfigForTenant(
                    tenantDomain, eventData.getEventName(), eventConfigManager);

            if (eventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildVerificationEventPayload(eventData);
                String eventUri = eventConfigManager.getEventUri(EventHookHandlerUtils.
                        resolveEventHandlerKey(schema, IdentityEventConstants.EventName.VERIFICATION));

                SecurityEventTokenPayload securityEventTokenPayload = securityEventTokenBuilder
                        .buildSecurityEventTokenPayload(eventPayload, eventUri, eventData);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);

            }
        } catch (Exception e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
            throw new IdentityEventException("Error while retrieving event publisher configuration for tenant.", e);
        }
    }
}
