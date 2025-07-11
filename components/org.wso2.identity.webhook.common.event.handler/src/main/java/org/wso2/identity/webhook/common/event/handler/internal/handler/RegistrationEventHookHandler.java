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
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;

public class RegistrationEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(RegistrationEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.REGISTRATION_EVENT_HOOK_NAME;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        boolean canHandle = false;
        try {
            if (!(messageContext instanceof IdentityEventMessageContext)) {
                log.debug("MessageContext is not of type IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }

            IdentityEventMessageContext identityContext = (IdentityEventMessageContext) messageContext;
            String eventName = identityContext.getEvent() != null ? identityContext.getEvent().getEventName() : null;

            if (eventName == null) {
                log.debug("Event name is null in IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }

            canHandle = isSupportedEvent(eventName);
            if (canHandle) {
                log.debug(eventName + " event can be handled.");
            } else {
                log.debug(eventName + " event cannot be handled.");
            }
        } catch (Exception e) {
            log.warn("Unexpected error occurred while evaluating event in RegistrationEventHookHandler.", e);
        }
        return canHandle;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();

            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping registration event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema
                        schema =
                        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                                eventProfile.getProfile());

                EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

                RegistrationEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                        .getRegistrationEventPayloadBuilder(schema);
                if (payloadBuilder == null) {
                    log.debug("Skipping registration event handling for event " +
                            eventProfile.getProfile());
                    continue;
                }
                // TODO Temporary fix to handle same event from different handlers.
                EventMetadata eventMetadata = getEventMetadata(eventProfile.getProfile(), event.getEventName());
                if (eventMetadata == null) {
                    log.debug("No event metadata found for event: " + event.getEventName() +
                            " in profile: " + eventProfile.getProfile());
                    continue;
                }
                String tenantDomain =
                        String.valueOf(
                                eventData.getEventParams().get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

                EventPayload eventPayload;
                String eventUri;

                List<Channel> channels = eventProfile.getChannels();
                // Get the channel URI for the channel with name "Registration Channel"
                Channel registrationChannel = channels.stream()
                        .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                        .findFirst()
                        .orElse(null);
                if (registrationChannel == null) {
                    log.debug("No channel found for registration event profile: " + eventProfile.getProfile());
                    continue;
                }

                eventUri = registrationChannel.getEvents().stream()
                        .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(),
                                channelEvent.getEventUri()))
                        .findFirst()
                        .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                        .orElse(null);

                EventContext eventContext = EventContext.builder()
                        .tenantDomain(tenantDomain)
                        .eventUri(registrationChannel.getUri())
                        .eventProfileName(eventProfile.getProfile())
                        .eventProfileVersion(EVENT_PROFILE_VERSION)
                        .build();

                boolean publisherCanHandleEvent = EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                        .canHandleEvent(eventContext);

                if (isUserRegistrationSuccessFlow(event.getEventName()) && publisherCanHandleEvent) {
                    eventPayload = payloadBuilder.buildRegistrationSuccessEvent(eventData);
                    SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                            .buildSecurityEventToken(eventPayload, eventUri);
                    EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                            .publish(securityEventTokenPayload, eventContext);
                } else if (isUserRegistrationFailedFlow(event.getEventName()) && publisherCanHandleEvent) {
                    eventPayload = payloadBuilder.buildRegistrationFailureEvent(eventData);
                    SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                            .buildSecurityEventToken(eventPayload, eventUri);
                    EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                            .publish(securityEventTokenPayload, eventContext);
                }
            }
        } catch (Exception e) {
            log.warn("Error while retrieving registration event publisher configuration for tenant.", e);
        }
    }

    private boolean isSupportedEvent(String eventName) {

        return isUserRegistrationSuccessFlow(eventName) || isUserRegistrationFailedFlow(eventName);
    }

    private boolean isUserRegistrationSuccessFlow(String eventName) {

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        Flow.Name flowName = (flow != null) ? flow.getName() : null;

        /*
        Event.POST_ADD_USER + Flow.Name.USER_REGISTRATION:
            Direct user registration, initiated either by an admin or the user.

        Event.POST_ADD_NEW_PASSWORD + Flow.Name.USER_REGISTRATION_INVITE_WITH_PASSWORD:
            User completes registration after being invited by an admin.

        Event.POST_SELF_SIGNUP_CONFIRM:
            Self-signup flow completed by the user.

         */
        return !Flow.Name.BULK_RESOURCE_UPDATE.equals(flowName) &&
                (IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS.equals(eventName)  ||
                        IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM.equals(eventName) ||
                        (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName) &&
                                Flow.Name.USER_REGISTRATION_INVITE_WITH_PASSWORD.equals(flowName)));
    }

    private boolean isUserRegistrationFailedFlow(String eventName) {

        return IdentityEventConstants.Event.USER_REGISTRATION_FAILED.equals(eventName);
    }

    private EventMetadata getEventMetadata(String eventProfile, String eventName) {

        String event = null;
        String channel = null;

        if (isUserRegistrationSuccessFlow(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.REGISTRATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_REGISTRATION_SUCCESS_EVENT;
        } else if (isUserRegistrationFailedFlow(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.REGISTRATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_REGISTRATION_FAILED_EVENT;
        }

        EventMetadata eventMetadata = EventMetadata.builder()
                .event(String.valueOf(event))
                .channel(String.valueOf(channel))
                .eventProfile(WSO2.name())
                .build();

        if (eventMetadata != null && eventProfile.equals(eventMetadata.getEventProfile())) {
            return eventMetadata;
        }

        return null;
    }
}
