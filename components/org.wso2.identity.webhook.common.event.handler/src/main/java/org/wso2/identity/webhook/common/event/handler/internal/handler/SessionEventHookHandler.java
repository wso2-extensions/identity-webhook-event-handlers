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
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.event.common.publisher.model.common.Subject;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

/**
 * This class handles session events and publishes them to the configured event publisher.
 */
public class SessionEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(SessionEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.SESSION_EVENT_HOOK_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping session event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {

                //TODO: Add the implementation to read the Event Schema Type from the Tenant Configuration
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema
                        schema =
                        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                                eventProfile.getProfile());

                SessionEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getSessionEventPayloadBuilder(schema);

                // TODO: Change this when the event schema type is added to the tenant configuration.
                if (payloadBuilder == null) {
                    log.debug("Skipping session event handling for profile " + eventProfile.getProfile());
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
                // Check if the event is enabled for the tenant
                EventPayload eventPayload = null;
                String eventUri = null;

                List<Channel> channels = eventProfile.getChannels();
                // Get the channel URI for the channel with name "Session Channel"
                Channel sessionChannel = channels.stream()
                        .filter(channel -> eventMetadata.getChannel().equals(channel.getName()))
                        .findFirst()
                        .orElse(null);
                if (sessionChannel == null) {
                    log.debug("No channel found for session event profile: " + eventProfile.getProfile());
                    continue;
                }

                eventUri = sessionChannel.getEvents().stream()
                        .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(),
                                channelEvent.getEventName()))
                        .findFirst()
                        .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                        .orElse(null);

                boolean isTopicExists = EventHookHandlerDataHolder.getInstance().getTopicManagementService()
                        .isTopicExists(sessionChannel.getUri(), Constants.EVENT_PROFILE_VERSION,
                                eventData.getAuthenticatedUser().getTenantDomain());

                if (isTopicExists) {
                    switch (IdentityEventConstants.EventName.valueOf(event.getEventName())) {
                        case USER_SESSION_TERMINATE:
                            eventPayload = payloadBuilder.buildSessionTerminateEvent(eventData);
                            break;
                        case SESSION_EXPIRE:
                            eventPayload = payloadBuilder.buildSessionExpireEvent(eventData);
                            break;
                        case SESSION_CREATE:
                            eventPayload = payloadBuilder.buildSessionCreateEvent(eventData);
                            break;
                        case SESSION_UPDATE:
                            eventPayload = payloadBuilder.buildSessionUpdateEvent(eventData);
                            break;

                        case SESSION_EXTEND:
                            eventPayload = payloadBuilder.buildSessionExtendEvent(eventData);
                            break;
                    }
                    if (eventPayload != null) {
                        Subject subject = null;
                        if (schema.equals(
                                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.CAEP)) {
                            subject = EventHookHandlerUtils.extractSubjectFromEventData(eventData);
                        }
                        String tenantDomain = eventData.getAuthenticatedUser().getTenantDomain();

                        SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils.
                                buildSecurityEventToken(eventPayload, eventUri, subject);
                        EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain,
                                sessionChannel.getUri());
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }
    }
}
