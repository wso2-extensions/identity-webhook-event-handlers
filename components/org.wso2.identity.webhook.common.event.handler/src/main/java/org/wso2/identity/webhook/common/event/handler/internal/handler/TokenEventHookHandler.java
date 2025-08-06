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
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
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
 * TokenEventHookHandler class.
 * This class is a placeholder for handling token-related events.
 * Currently, it does not contain any methods or properties.
 */
public class TokenEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(TokenEventHookHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {
        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();

            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping token event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {

                //TODO: Add the implementation to read the Event Schema Type from the Tenant Configuration
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema
                        schema =
                        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                                eventProfile.getProfile());

                EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

                TokenEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getTokenEventPayloadBuilder(schema);

                if (payloadBuilder == null) {
                    log.debug("Skipping token event handling for event " +
                            eventProfile.getProfile());
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
                String tenantDomain = eventData.getTenantDomain();

                EventPayload eventPayload;
                String eventUri;

                List<Channel> channels = eventProfile.getChannels();
                Channel tokenChannel = channels.stream()
                        .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                        .findFirst()
                        .orElse(null);
                if (tokenChannel == null) {
                    log.debug("No channel found for token event profile: " + eventProfile.getProfile());
                    continue;
                }

                eventUri = tokenChannel.getEvents().stream()
                        .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(),
                                channelEvent.getEventUri()))
                        .findFirst()
                        .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                        .orElse(null);

                EventContext eventContext = EventContext.builder()
                        .tenantDomain(tenantDomain)
                        .eventUri(tokenChannel.getUri())
                        .eventProfileName(eventProfile.getProfile())
                        .eventProfileVersion(EVENT_PROFILE_VERSION)
                        .build();

                boolean publisherCanHandleEvent = EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                        .canHandleEvent(eventContext);

                if ((IdentityEventConstants.Event.TOKEN_REVOKED.equals(event.getEventName())) &&
                        publisherCanHandleEvent) {
                    eventPayload = payloadBuilder.buildAccessTokenRevokeEvent(eventData);
                    SecurityEventTokenPayload securityEventTokenPayload =
                            EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
                    EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                            .publish(securityEventTokenPayload, eventContext);
                } else if (IdentityEventConstants.Event.TOKEN_ISSUED.equals(event.getEventName()) &&
                        publisherCanHandleEvent) {
                    eventPayload = payloadBuilder.buildAccessTokenIssueEvent(eventData);
                    SecurityEventTokenPayload securityEventTokenPayload =
                            EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
                    EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                            .publish(securityEventTokenPayload, eventContext);
                }
            }
        } catch (Exception e) {
            log.warn("Error while executing token event webhook handler.", e);
        }
    }


    @Override
    public String getName() {

        return Constants.TOKEN_EVENT_HOOK_NAME;
    }
}
