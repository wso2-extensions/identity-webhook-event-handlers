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
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

/**
 * This class handles credential events and builds the event payload.
 */
public class CredentialEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(CredentialEventHookHandler.class);

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

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();

            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping credential event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {

                //TODO: Add the implementation to read the Event Schema Type from the Tenant Configuration
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema schema =
                        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                                eventProfile.getProfile());

                EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

                CredentialEventPayloadBuilder payloadBuilder =
                        PayloadBuilderFactory.getCredentialEventPayloadBuilder(schema);

                String tenantDomain = String.valueOf(
                        eventData.getEventParams().get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

                if (payloadBuilder == null) {
                    log.debug("Skipping credential change event handling for profile " + eventProfile.getProfile());
                    continue;
                }
                EventMetadata eventMetadata =
                        EventHookHandlerUtils.getEventProfileManagerByProfile(eventProfile.getProfile(),
                                event.getEventName());
                if (eventMetadata == null) {
                    log.debug("No event metadata found for event: " + event.getEventName() + " in profile: " +
                            eventProfile.getProfile());
                    continue;
                }
                EventPayload eventPayload;
                String eventUri;

                List<Channel> channels = eventProfile.getChannels();

                Channel credentialChangeChannel =
                        channels.stream().filter(channel -> eventMetadata.getChannel().equals(channel.getName()))
                                .findFirst().orElse(null);
                if (credentialChangeChannel == null) {
                    log.debug("No channel found for credential change event profile: " + eventProfile.getProfile());
                    continue;
                }

                eventUri = credentialChangeChannel.getEvents().stream()
                        .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventName()))
                        .findFirst().map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                        .orElse(null);

                boolean isTopicExists = EventHookHandlerDataHolder.getInstance().getTopicManagementService()
                        .isTopicExists(credentialChangeChannel.getUri(), Constants.EVENT_PROFILE_VERSION, tenantDomain);

                if (isCredentialUpdateFlow(event.getEventName()) && isTopicExists) {
                    eventPayload = payloadBuilder.buildCredentialUpdateEvent(eventData);
                    SecurityEventTokenPayload securityEventTokenPayload =
                            EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
                    EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain,
                            credentialChangeChannel.getUri());
                }
            }
        } catch (Exception e) {
            log.debug("Error while retrieving credential change event publisher configuration for tenant.", e);
        }
    }

    private boolean isSupportedEvent(String eventName) {

        return isCredentialUpdateFlow(eventName);
    }

    public boolean isCredentialUpdateFlow(String eventName) {

        if (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName)) {
            Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
            Flow.Name flowName = (flow != null) ? flow.getName() : null;

            return !Flow.Name.USER_REGISTRATION_INVITE_WITH_PASSWORD.equals(flowName);
        }

        return IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(eventName);
    }
}
