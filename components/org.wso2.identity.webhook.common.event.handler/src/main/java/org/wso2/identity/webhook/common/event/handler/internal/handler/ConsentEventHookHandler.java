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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_ADD_RECEIPT;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_AUTHORIZE_CONSENT;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_REVOKE_RECEIPT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.CONSENT_REVOKED_EVENT;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
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
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentEventPayloadBuilder;
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
 * Consent Event Hook Handler.
 */
public class ConsentEventHookHandler extends AbstractEventHandler {

    private static final Log LOG = LogFactory.getLog(ConsentEventHookHandler.class);

    @Override
    public String getName() {

        return Constants.CONSENT_EVENT_HOOK_NAME;
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
            if (StringUtils.isBlank(eventName)) {
                LOG.debug("Event name is null in IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            canHandle = POST_ADD_RECEIPT.equals(eventName) ||
                    POST_AUTHORIZE_CONSENT.equals(eventName) ||
                    POST_REVOKE_RECEIPT.equals(eventName);
            if (LOG.isDebugEnabled()) {
                LOG.debug(eventName + (canHandle ? " event can be handled." : " event cannot be handled."));
            }
        } catch (Exception e) {
            LOG.warn("Unexpected error occurred while evaluating event in ConsentEventHookHandler.", e);
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
                        "Skipping consent event handling.");
                return;
            }
            EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
            for (EventProfile eventProfile : eventProfileList) {
                handleEventForProfile(event, eventData, eventProfile);
            }
        } catch (Exception e) {
            LOG.warn("Error while handling consent event.", e);
        }
    }

    private void handleEventForProfile(Event event, EventData eventData, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        EventSchema schema = EventSchema.valueOf(eventProfile.getProfile());
        ConsentEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getConsentEventPayloadBuilder(schema);
        if (payloadBuilder == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Skipping consent event handling for profile " + eventProfile.getProfile());
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

        Channel consentChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (consentChannel == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No channel found for consent event profile: " + eventProfile.getProfile());
            }
            return;
        }

        String eventUri = consentChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        String tenantDomain = eventData.getTenantDomain();
        publishEvent(tenantDomain, consentChannel, eventUri, eventMetadata.getEvent(), eventProfile.getProfile(),
                payloadBuilder, eventData);
    }

    private void publishEvent(String tenantDomain, Channel consentChannel, String eventUri,
                              String eventType, String eventProfileName,
                              ConsentEventPayloadBuilder payloadBuilder, EventData eventData)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(consentChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        List<EventPayload> eventPayloads = CONSENT_REVOKED_EVENT.equals(eventType)
                ? payloadBuilder.buildConsentRevokedEvent(eventData)
                : payloadBuilder.buildConsentAddedEvent(eventData);

        for (EventPayload eventPayload : eventPayloads) {
            SecurityEventTokenPayload securityEventTokenPayload =
                    EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
            EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                    .publish(securityEventTokenPayload, eventContext);
        }
    }
}
