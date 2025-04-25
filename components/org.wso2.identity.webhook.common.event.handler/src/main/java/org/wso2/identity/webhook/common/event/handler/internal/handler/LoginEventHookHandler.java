/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

/**
 * Login Event Hook Handler.
 */
public class LoginEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(LoginEventHookHandler.class);
    private final EventConfigManager eventConfigManager;

    public LoginEventHookHandler(EventConfigManager eventConfigManager) {

        this.eventConfigManager = eventConfigManager;
    }

    @Override
    public String getName() {

        return Constants.LOGIN_EVENT_HOOK_NAME;
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

    private boolean isSupportedEvent(String eventName) {

        return IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(eventName) ||
                IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(eventName) ||
                IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name().equals(eventName);
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        if (eventData.getAuthenticationContext().isPassiveAuthenticate()) {
            return;
        }

        //TODO: Add the implementation to read the Event Schema Type from the Tenant Configuration
        String schema = Constants.WSO2_EVENT_SCHEMA;
        LoginEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                .getLoginEventPayloadBuilder(schema);
        EventPublisherConfig loginEventPublisherConfig = null;
        try {
            loginEventPublisherConfig = EventHookHandlerUtils.getEventPublisherConfigForTenant(
                    eventData.getAuthenticationContext().getLoginTenantDomain(),
                    event.getEventName(), eventConfigManager);

            EventPayload eventPayload;
            String eventUri;

            if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(event.getEventName()) &&
                    loginEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildAuthenticationSuccessEvent(eventData);
                eventUri = eventConfigManager.getEventUri(EventHookHandlerUtils
                        .resolveEventHandlerKey(schema, IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS));
                String tenantDomain = eventData.getAuthenticationContext().getLoginTenantDomain();
                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            } else if (IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name()
                    .equals(event.getEventName()) &&
                    loginEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildAuthenticationFailedEvent(eventData);
                eventUri = eventConfigManager.getEventUri(EventHookHandlerUtils.
                        resolveEventHandlerKey(schema, IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE));
                String tenantDomain = eventData.getAuthenticationContext().getLoginTenantDomain();
                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            }
        } catch (IdentityEventException e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }
    }
}
