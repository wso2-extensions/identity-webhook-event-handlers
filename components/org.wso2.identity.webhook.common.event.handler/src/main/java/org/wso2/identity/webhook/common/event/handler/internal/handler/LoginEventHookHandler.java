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
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

/**
 * Login Event Hook Handler.
 */
public class LoginEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(LoginEventHookHandler.class);

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

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping login event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {

                //TODO: Add the implementation to read the Event Schema Type from the Tenant Configuration
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema
                        schema =
                        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                                eventProfile.getProfile());
                LoginEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                        .getLoginEventPayloadBuilder(schema);

                // TODO: Change this when the event schema type is added to the tenant configuration.
                if (payloadBuilder == null) {
                    log.debug("Skipping login event handling for profile " + eventProfile.getProfile());
                    continue;
                }
                EventMetadata eventMetadata =
                        EventHookHandlerUtils.getEventProfileManagerByProfile(eventProfile.getProfile(),
                                event.getEventName());
                if (eventMetadata == null) {
                    log.debug("No event metadata found for event: " + event.getEventName() +
                            " in profile: " + eventProfile.getProfile());
                    continue;
                }
                String tenantDomain = eventData.getAuthenticationContext().getLoginTenantDomain();

                EventPayload eventPayload;
                String eventUri;

                List<Channel> channels = eventProfile.getChannels();
                // Get the channel URI for the channel with name "Login Channel"
                Channel loginChannel = channels.stream()
                        .filter(channel -> eventMetadata.getChannel().equals(channel.getName()))
                        .findFirst()
                        .orElse(null);
                if (loginChannel == null) {
                    log.debug("No channel found for login event profile: " + eventProfile.getProfile());
                    continue;
                }

                eventUri = loginChannel.getEvents().stream()
                        .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(),
                                channelEvent.getEventName()))
                        .findFirst()
                        .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                        .orElse(null);

                boolean isTopicExists = EventHookHandlerDataHolder.getInstance().getTopicManagementService()
                        .isTopicExists(loginChannel.getUri(), Constants.EVENT_PROFILE_VERSION, tenantDomain);

                if (isTopicExists) {
                    switch (IdentityEventConstants.EventName.valueOf(event.getEventName())) {
                        case AUTHENTICATION_SUCCESS:
                            eventPayload = payloadBuilder.buildAuthenticationSuccessEvent(eventData);
                            break;
                        case AUTHENTICATION_STEP_FAILURE:
                        case AUTHENTICATION_FAILURE:
                            eventPayload = payloadBuilder.buildAuthenticationFailedEvent(eventData);
                            break;
                        default:
                            throw new IdentityRuntimeException("Unsupported event type: " + event.getEventName());
                    }
                    SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                            .buildSecurityEventToken(eventPayload, eventUri);
                    EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain,
                            loginChannel.getUri());
                }
            }
        } catch (Exception e) {
            log.debug("Error while retrieving login event publisher configuration for tenant.", e);
        }
    }
}
