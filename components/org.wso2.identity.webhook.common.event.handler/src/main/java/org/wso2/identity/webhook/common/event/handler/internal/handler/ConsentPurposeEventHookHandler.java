/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_ADD_PURPOSE_VERSION;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentPurposeEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;

/**
 * Consent Purpose Event Hook Handler.
 */
public class ConsentPurposeEventHookHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(ConsentPurposeEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.CONSENT_PURPOSE_EVENT_HOOK_NAME;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        boolean canHandle = false;
        try {
            if (!(messageContext instanceof IdentityEventMessageContext identityContext)) {
                LOG.debug("MessageContext is not of type IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            String eventName = identityContext.getEvent() != null ? identityContext.getEvent().getEventName() : null;
            if (eventName == null) {
                LOG.debug("Event name is null in IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            canHandle = POST_ADD_PURPOSE_VERSION.equals(eventName);
            if (LOG.isDebugEnabled()) {
                LOG.debug(eventName + (canHandle ? " event can be handled." : " event cannot be handled."));
            }
        } catch (Exception e) {
            LOG.warn("Unexpected error occurred while evaluating event in ConsentPurposeEventHookHandler.", e);
        }
        return canHandle;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();
            if (eventProfileList.isEmpty()) {
                LOG.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping consent purpose event handling.");
                return;
            }
            EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
            for (EventProfile eventProfile : eventProfileList) {
                handleEventForProfile(event, eventData, eventProfile);
            }
        } catch (Exception e) {
            LOG.warn("Error while handling consent purpose event.", e);
        }
    }

    private void handleEventForProfile(Event event, EventData eventData, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        EventSchema schema = EventSchema.valueOf(eventProfile.getProfile());
        ConsentPurposeEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getConsentPurposeEventPayloadBuilder(schema);
        if (payloadBuilder == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipping consent purpose event handling for profile " + eventProfile.getProfile());
            }
            return;
        }

        EventMetadata eventMetadata = EventHookHandlerUtils.getEventProfileManagerByProfile(
                eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No event metadata found for event: " + event.getEventName() +
                        " in profile: " + eventProfile.getProfile());
            }
            return;
        }

        Channel consentPurposeChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (consentPurposeChannel == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No channel found for consent purpose event profile: " + eventProfile.getProfile());
            }
            return;
        }

        String eventUri = consentPurposeChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        String tenantDomain = eventData.getTenantDomain();
        publishEvent(tenantDomain, consentPurposeChannel, eventUri, eventProfile.getProfile(),
                payloadBuilder, eventData, event.getEventName());
    }

    private void publishEvent(String tenantDomain, Channel consentPurposeChannel, String eventUri,
                              String eventProfileName, ConsentPurposeEventPayloadBuilder payloadBuilder,
                              EventData eventData, String eventName)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(consentPurposeChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload;
        if (POST_ADD_PURPOSE_VERSION.equals(eventName)) {
            eventPayload = payloadBuilder.buildPurposeVersionAddedEvent(eventData);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Unsupported consent purpose event: " + eventName);
            }
            return;
        }

        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }
}
