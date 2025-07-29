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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.PolicyEnum;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.model.WebhookMetadataProperties;
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
            log.warn("Unexpected error occurred while evaluating event in LoginEventHookHandler.", e);
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
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema
                        schema =
                        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                                eventProfile.getProfile());
                LoginEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                        .getLoginEventPayloadBuilder(schema);

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

                List<Channel> channels = eventProfile.getChannels();
                // Get the channel URI for the channel with name "Login Channel"
                Channel loginChannel = channels.stream()
                        .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                        .findFirst()
                        .orElse(null);
                if (loginChannel == null) {
                    log.debug("No channel found for login event profile: " + eventProfile.getProfile());
                    continue;
                }

                String eventUri = loginChannel.getEvents().stream()
                        .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(),
                                channelEvent.getEventUri()))
                        .findFirst()
                        .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                        .orElse(null);

                String applicationNameInEvent = eventData.getAuthenticationContext().getServiceProviderName();
                //TODO: Remove this once the system application type is introduced.
                boolean isEventTriggeredForSystemApplication = StringUtils.isNotBlank(applicationNameInEvent)
                        && "Console".equals(applicationNameInEvent);

                if (isEventTriggeredForSystemApplication) {
                    log.debug("Event trigger for system application: " + applicationNameInEvent +
                            ". Skipping event handling for login event profile: " + eventProfile.getProfile());
                    return;
                }

                String tenantDomain = eventData.getAuthenticationContext().getLoginTenantDomain();

                publishEvent(tenantDomain, loginChannel, eventUri, eventProfile.getProfile(),
                        payloadBuilder, eventData, event.getEventName());

                // If parent tenant configured webhook with policy immediate sub orgs, publish the event to parent tenant as well.
                String parentOrganizationId;
                String parentTenantDomain = null;
                IdentityContext identityContext = IdentityContext.getThreadLocalIdentityContext();
                if (identityContext.getOrganization() != null) {
                    parentOrganizationId = identityContext.getOrganization().getParentOrganizationId();
                    if (parentOrganizationId != null) {
                        log.debug("Resolving parent tenant domain for organization: " + parentOrganizationId);
                        parentTenantDomain = EventHookHandlerDataHolder.getInstance()
                                .getOrganizationManager().resolveTenantDomain(parentOrganizationId);
                    }
                }
                if (parentTenantDomain != null) {
                    WebhookMetadataProperties metadataProperties =
                            EventHookHandlerDataHolder.getInstance().getWebhookMetadataService()
                                    .getWebhookMetadataProperties(parentTenantDomain);
                    if (metadataProperties != null &&
                            Objects.equals(metadataProperties.getOrganizationPolicy().getPolicyCode(),
                                    PolicyEnum.IMMEDIATE_EXISTING_AND_FUTURE_ORGS.getPolicyCode())) {
                        publishEvent(parentTenantDomain, loginChannel, eventUri, eventProfile.getProfile(),
                                payloadBuilder, eventData, event.getEventName());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Error while retrieving login event publisher configuration for tenant.", e);
        }
    }

    private void publishEvent(String tenantDomain, Channel loginChannel, String eventUri, String eventProfileName,
                              LoginEventPayloadBuilder payloadBuilder, EventData eventData, String eventName)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(loginChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(Constants.EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload;
        switch (IdentityEventConstants.EventName.valueOf(eventName)) {
            case AUTHENTICATION_SUCCESS:
                eventPayload = payloadBuilder.buildAuthenticationSuccessEvent(eventData);
                break;
            case AUTHENTICATION_STEP_FAILURE:
            case AUTHENTICATION_FAILURE:
                eventPayload = payloadBuilder.buildAuthenticationFailedEvent(eventData);
                break;
            default:
                throw new IdentityRuntimeException("Unsupported event type: " + eventName);
        }

        log.debug("Publishing login event: " + eventName + " for tenant: " + tenantDomain +
                " with event URI: " + eventUri + " and profile: " + eventProfileName);
        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }
}
