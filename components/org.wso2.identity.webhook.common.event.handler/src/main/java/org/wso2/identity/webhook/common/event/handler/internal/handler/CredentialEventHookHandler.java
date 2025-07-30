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
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.PolicyEnum;
import org.wso2.carbon.identity.webhook.metadata.api.exception.WebhookMetadataException;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.model.WebhookMetadataProperties;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
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
            log.debug(eventName + (canHandle ? " event can be handled." : " event cannot be handled."));
        } catch (Exception e) {
            log.warn("Unexpected error occurred while evaluating event in CredentialEventHookHandler.", e);
        }
        return canHandle;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();

            if (eventProfileList.isEmpty()) {
                log.warn(
                        "No event profiles found in the webhook metadata service. Skipping credential event handling.");
                return;
            }

            for (EventProfile eventProfile : eventProfileList) {
                handleEventForProfile(event, eventProfile);
            }
        } catch (Exception e) {
            log.warn("Error while retrieving credential change event publisher configuration for tenant.", e);
        }
    }

    private void handleEventForProfile(Event event, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException, OrganizationManagementException,
            WebhookMetadataException {
        // Prepare schema, payload builder, and event data
        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema schema =
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                        eventProfile.getProfile());
        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
        CredentialEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getCredentialEventPayloadBuilder(schema);

        if (payloadBuilder == null) {
            log.debug("Skipping credential change event handling for profile " + eventProfile.getProfile());
            return;
        }

        // Get event metadata and channel
        EventMetadata eventMetadata = EventHookHandlerUtils.getEventProfileManagerByProfile(
                eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            log.debug("No event metadata found for event: " + event.getEventName() + " in profile: " +
                    eventProfile.getProfile());
            return;
        }

        Channel credentialChangeChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst().orElse(null);
        if (credentialChangeChannel == null) {
            log.debug("No channel found for credential change event profile: " + eventProfile.getProfile());
            return;
        }

        String eventUri = credentialChangeChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst().map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        // Publish for current accessing org
        String tenantDomain = String.valueOf(
                eventData.getEventParams().get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));
        publishCredentialEvent(tenantDomain, credentialChangeChannel, eventUri, eventProfile.getProfile(),
                payloadBuilder, eventData, event.getEventName());

        // Publish for immediate parent org if policy allows
        String parentTenantDomain = resolveParentTenantDomain();
        if (parentTenantDomain != null && isParentPolicyImmediateOrgs(parentTenantDomain)) {
            publishCredentialEvent(parentTenantDomain, credentialChangeChannel, eventUri, eventProfile.getProfile(),
                    payloadBuilder, eventData, event.getEventName());
        }
    }

    private boolean isSupportedEvent(String eventName) {

        return isCredentialUpdateFlow(eventName);
    }

    public boolean isCredentialUpdateFlow(String eventName) {

        if (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName)) {
            Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
            Flow.Name flowName = (flow != null) ? flow.getName() : null;
            return Flow.Name.PASSWORD_RESET.equals(flowName);
        }
        return IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(eventName);
    }

    private void publishCredentialEvent(String tenantDomain, Channel credentialChangeChannel, String eventUri,
                                        String eventProfileName, CredentialEventPayloadBuilder payloadBuilder,
                                        EventData eventData, String eventName)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(credentialChangeChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload;
        if (isCredentialUpdateFlow(eventName)) {
            eventPayload = payloadBuilder.buildCredentialUpdateEvent(eventData);
        } else {
            throw new IdentityRuntimeException("Unsupported event type: " + eventName);
        }

        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }

    private String resolveParentTenantDomain() throws OrganizationManagementException {

        IdentityContext identityContext = IdentityContext.getThreadLocalIdentityContext();
        if (identityContext.getOrganization() != null) {
            String parentOrganizationId = identityContext.getOrganization().getParentOrganizationId();
            if (parentOrganizationId != null) {
                return EventHookHandlerDataHolder.getInstance()
                        .getOrganizationManager().resolveTenantDomain(parentOrganizationId);
            }
        }
        return null;
    }

    private boolean isParentPolicyImmediateOrgs(String parentTenantDomain) throws WebhookMetadataException {

        WebhookMetadataProperties metadataProperties =
                EventHookHandlerDataHolder.getInstance().getWebhookMetadataService()
                        .getWebhookMetadataProperties(parentTenantDomain);
        return metadataProperties != null &&
                Objects.equals(metadataProperties.getOrganizationPolicy().getPolicyCode(),
                        PolicyEnum.IMMEDIATE_EXISTING_AND_FUTURE_ORGS.getPolicyCode());
    }
}
