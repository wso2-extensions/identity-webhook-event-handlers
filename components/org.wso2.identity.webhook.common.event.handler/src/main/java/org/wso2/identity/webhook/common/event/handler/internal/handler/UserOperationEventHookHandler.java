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
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.PRE_DELETE_USER_ID;

/**
 * User Operation Event Hook Handler.
 */
public class UserOperationEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(UserOperationEventHookHandler.class);
    private final EventConfigManager eventConfigManager;

    public UserOperationEventHookHandler(EventConfigManager eventConfigManager) {

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

        return IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(eventName) ||
                IdentityEventConstants.Event.PRE_DELETE_USER_WITH_ID.equals(eventName) ||
                IdentityEventConstants.Event.POST_DELETE_USER.equals(eventName) ||
                IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT.equals(eventName);
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        UserOperationEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                .getUserOperationEventPayloadBuilder(EventSchema.WSO2.name());
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
                        eventConfigManager.getEventUri(
                                Constants.EventHandlerKey.WSO2.POST_UPDATE_USER_LIST_OF_ROLE_EVENT);
                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            } else if (IdentityEventConstants.Event.PRE_DELETE_USER_WITH_ID.equals(event.getEventName()) &&
                    userOperationEventPublisherConfig.isPublishEnabled()) {

                String userId =
                        (String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_ID);
                // Setting the thread-local to keep user-ID for use when publishing post delete user event.
                IdentityUtil.threadLocalProperties.get().put(PRE_DELETE_USER_ID, userId);

            } else if (IdentityEventConstants.Event.POST_DELETE_USER.equals(event.getEventName()) &&
                    userOperationEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildUserDeleteEvent(eventData);
                eventUri = eventConfigManager.getEventUri(Constants.EventHandlerKey.WSO2.POST_DELETE_USER_EVENT);
                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            } else if (IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT.equals(event.getEventName()) &&
                    userOperationEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildUserUnlockAccountEvent(eventData);
                eventUri = eventConfigManager.getEventUri(Constants.EventHandlerKey.WSO2.POST_UNLOCK_ACCOUNT_EVENT);
                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            }
        } catch (IdentityEventException e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }
    }
}
