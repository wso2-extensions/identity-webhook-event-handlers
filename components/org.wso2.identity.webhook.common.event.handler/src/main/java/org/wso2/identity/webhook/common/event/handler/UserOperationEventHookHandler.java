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

package org.wso2.identity.webhook.common.event.handler;

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
import org.wso2.identity.webhook.common.event.handler.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.common.event.handler.model.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils;

import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_SCHEMA_TYPE_WSO2;

/**
 * User Operation Event Hook Handler.
 */
public class UserOperationEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(UserOperationEventHookHandler.class);
    private final EventHookHandlerUtils eventHookHandlerUtils;
    private final EventConfigManager eventConfigManager;

    public UserOperationEventHookHandler(EventHookHandlerUtils eventHookHandlerUtils,
                                         EventConfigManager eventConfigManager) {

        this.eventHookHandlerUtils = eventHookHandlerUtils;
        this.eventConfigManager = eventConfigManager;
    }

    @Override
    public String getName() {

        return Constants.USER_OPERATION_EVENT_HOOK_NAME;
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

        return IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(eventName);
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = eventHookHandlerUtils.buildEventDataProvider(event);

        UserOperationEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                .getUserOperationEventPayloadBuilder(EVENT_SCHEMA_TYPE_WSO2);
        EventPublisherConfig userOperationEventPublisherConfig;
        try {

            String tenantDomain =
                    String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

            userOperationEventPublisherConfig =
                    eventConfigManager.getEventPublisherConfigForTenant(tenantDomain, event.getEventName());

            EventPayload eventPayload;
            String eventUri;

            if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(event.getEventName()) &&
                    userOperationEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildUserGroupUpdateEvent(eventData);
                eventUri =
                        eventConfigManager.getEventUri(Constants.EventHandlerKey.POST_UPDATE_USER_LIST_OF_ROLE_EVENT);
                SecurityEventTokenPayload securityEventTokenPayload = eventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                eventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            }
        } catch (IdentityEventException e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }
    }
}
