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
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.model.common.Subject;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.VerificationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;

/**
 * This class is responsible for handling verification events.
 */
public class VerificationEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(VerificationEventHookHandler.class);

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
            log.warn("Unexpected error occurred while evaluating event in VerificationEventHookHandler.", e);
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

        try {
            EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping verification event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema
                        schema =
                        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                                eventProfile.getProfile());
                VerificationEventPayloadBuilder payloadBuilder =
                        PayloadBuilderFactory.getVerificationEventPayloadBuilder(schema);

                if (payloadBuilder == null) {
                    log.debug("Skipping verification event handling for profile " + eventProfile.getProfile());
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

                EventPayload eventPayload;
                String eventUri;

                String tenantDomain = eventData.getAuthenticationContext().getTenantDomain();

                List<Channel> channels = eventProfile.getChannels();
                // Get the channel URI for the channel with name "Verification Channel"
                Channel verificationChannel = channels.stream()
                        .filter(channel -> eventMetadata.getChannel().equals(channel.getName()))
                        .findFirst()
                        .orElse(null);
                if (verificationChannel == null) {
                    log.debug("No channel found for verification event profile: " + eventProfile.getProfile());
                    continue;
                }

                eventUri = verificationChannel.getEvents().stream()
                        .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(),
                                channelEvent.getEventName()))
                        .findFirst()
                        .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                        .orElse(null);

                EventContext eventContext = EventContext.builder()
                        .tenantDomain(tenantDomain)
                        .eventUri(verificationChannel.getUri())
                        .eventProfileName(eventProfile.getProfile())
                        .eventProfileVersion(EVENT_PROFILE_VERSION)
                        .build();

                boolean publisherCanHandleEvent = EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                        .canHandleEvent(eventContext);

                if (publisherCanHandleEvent) {
                    eventPayload = payloadBuilder.buildVerificationEventPayload(eventData);
                    Subject subject = EventHookHandlerUtils.buildVerificationSubject(eventData);

                    SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils.
                            buildSecurityEventToken(eventPayload, eventUri, subject);
                    EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                            .publish(securityEventTokenPayload, eventContext);

                }
            }
        } catch (Exception e) {
            log.warn("Error while retrieving event publisher configuration for tenant.", e);
        }
    }
}
