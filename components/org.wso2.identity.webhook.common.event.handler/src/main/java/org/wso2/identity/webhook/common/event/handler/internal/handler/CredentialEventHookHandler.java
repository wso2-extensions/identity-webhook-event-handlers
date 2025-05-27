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
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

/**
 * This class handles credential events and builds the event payload.
 */
public class CredentialEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(CredentialEventHookHandler.class);
    private final EventConfigManager eventConfigManager;

    public CredentialEventHookHandler(EventConfigManager eventConfigManager) {

        this.eventConfigManager = eventConfigManager;
    }

    @Override
    public String getName() {

        return Constants.CREDENTIAL_EVENT_HOOK_NAME;
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
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        CredentialEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                .getCredentialEventPayloadBuilder(EventSchema.WSO2);

        EventPublisherConfig credentialEventPublisherConfig;

        try {
            String tenantDomain =
                    String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

            credentialEventPublisherConfig =
                    eventConfigManager.getEventPublisherConfigForTenant(tenantDomain, event.getEventName());

            EventPayload eventPayload;
            String eventUri;

            if ((IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(event.getEventName()) ||
                    IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(event.getEventName())) &&
                    credentialEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildCredentialUpdateEvent(eventData);
                eventUri = eventConfigManager.getEventUri(Constants.EventHandlerKey.WSO2.POST_UPDATE_USER_CREDENTIAL);
                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            }
        } catch (Exception e) {
            throw new IdentityEventException("Error occurred while building event payload", e);
        }
    }

    private boolean isSupportedEvent(String eventName) {

        return IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName) ||
                IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(eventName);
    }
}
