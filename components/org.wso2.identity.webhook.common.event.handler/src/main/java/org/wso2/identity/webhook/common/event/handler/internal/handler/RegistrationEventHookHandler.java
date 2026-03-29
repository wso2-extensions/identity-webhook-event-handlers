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
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySetting;
import org.wso2.carbon.identity.compatibility.settings.core.service.CompatibilitySettingsService;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.event.publisher.api.exception.EventPublisherException;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.flow.mgt.FlowMgtService;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowCompletionConfig;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.flow.mgt.model.FlowConfigDTO;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.REGISTRATION_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_REGISTRATION_FAILED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_REGISTRATION_SUCCESS_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;

/**
 * Event handler for registration events.
 * This handler processes user registration success and failure events, publishing them to the appropriate channels
 * based on the event profiles defined in the webhook metadata service.
 */
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
            Event identityEvent = identityContext.getEvent();
            if (identityEvent == null || identityEvent.getEventName() == null) {
                log.debug("Event or event name is null in IdentityEventMessageContext. Cannot handle the event.");
                return false;
            }
            canHandle = isSupportedEvent(identityEvent);
            log.debug(identityEvent.getEventName() +
                    (canHandle ? " event can be handled." : " event cannot be handled."));
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
                log.warn(
                        "No event profiles found in the webhook metadata service. Skipping registration event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventForProfile(event, eventProfile);
            }
        } catch (Exception e) {
            log.warn("Error while retrieving registration event publisher configuration for tenant.", e);
        }
    }

    private void handleEventForProfile(Event event, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        // Prepare schema, payload builder, and event data
        EventSchema schema = EventSchema.valueOf(eventProfile.getProfile());
        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
        RegistrationEventPayloadBuilder payloadBuilder =
                PayloadBuilderFactory.getRegistrationEventPayloadBuilder(schema);

        if (payloadBuilder == null) {
            log.debug("Skipping registration event handling for event " + eventProfile.getProfile());
            return;
        }

        // Get event metadata and channel
        EventMetadata eventMetadata = getEventMetadata(eventProfile.getProfile(), event);
        if (eventMetadata == null) {
            log.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile());
            return;
        }

        Channel registrationChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (registrationChannel == null) {
            log.debug("No channel found for registration event profile: " + eventProfile.getProfile());
            return;
        }

        String eventUri = registrationChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        // Publish for current accessing org
        String tenantDomain = eventData.getTenantDomain();
        publishRegistrationEvent(tenantDomain, registrationChannel, eventUri, eventProfile.getProfile(),
                payloadBuilder, eventData, event);
    }

    /**
     * Checks whether the given event is a supported registration event.
     *
     * @param event The event to evaluate.
     * @return true if the event is a supported registration success or failure event.
     */
    private boolean isSupportedEvent(Event event) {

        return isUserRegistrationSuccessFlow(event) || isUserRegistrationFailedFlow(event.getEventName());
    }

    /**
     * Determines whether the event corresponds to a user registration success flow.
     *
     * @param event The event to evaluate.
     * @return true if the event belongs to a registration success flow and should be handled.
     */
    private boolean isUserRegistrationSuccessFlow(Event event) {

        String eventName = event.getEventName();
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        Flow.Name flowName = (flow != null) ? flow.getName() : null;
        if (Flow.Name.BULK_RESOURCE_UPDATE.equals(flowName)) {
            return false;
        }
        if (IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS.equals(eventName)) {
            return true;
        }
        if (IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM.equals(eventName)) {
            return !shouldSkipRegistrationEventForFlowConfig(event);
        }
        return IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName) &&
                Flow.Name.INVITE.equals(flowName);
    }

    private boolean isUserRegistrationFailedFlow(String eventName) {

        return IdentityEventConstants.Event.USER_REGISTRATION_FAILED.equals(eventName);
    }

    /**
     * Determines whether the registration webhook event should be skipped based on the registration flow config.
     * If the identity.xml config is disabled, it takes precedence and the event is not skipped. If enabled,
     * the compatibility setting for the tenant is honored to determine whether skipping applies.
     *
     * @param event The event whose properties are used to resolve the tenant domain.
     * @return true if the event should be skipped, false otherwise.
     */
    private boolean shouldSkipRegistrationEventForFlowConfig(Event event) {

        String skipConfig = IdentityUtil.getProperty(
                Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED);
        if (!Boolean.parseBoolean(skipConfig)) {
            return false;
        }
        try {
            Map<String, Object> eventProperties = event.getEventProperties();
            if (eventProperties == null ||
                    !eventProperties.containsKey(IdentityEventConstants.EventProperty.TENANT_DOMAIN) ||
                    eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN) == null) {
                log.warn("Tenant domain not found in event properties. Defaulting to not skip.");
                return false;
            }
            String tenantDomain = String.valueOf(
                    eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

            if (!isSkipSignupConfirmationEnabledByCompatibilitySetting(tenantDomain)) {
                return false;
            }

            FlowMgtService flowMgtService = EventHookHandlerDataHolder.getInstance().getFlowMgtService();
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            FlowConfigDTO flowConfig = flowMgtService.getFlowConfig(
                    FlowTypes.REGISTRATION.getType(), tenantId);
            if (flowConfig == null || !Boolean.TRUE.equals(flowConfig.getIsEnabled())) {
                return false;
            }
            String accountLockConfig = flowConfig.getFlowCompletionConfig(
                    FlowCompletionConfig.IS_ACCOUNT_LOCK_ON_CREATION_ENABLED);
            return !Boolean.parseBoolean(accountLockConfig);
        } catch (Exception e) {
            log.warn("Error while checking registration flow config. Defaulting to not skip.", e);
            return false;
        }
    }

    /**
     * Checks the compatibility setting for the tenant to determine whether skip signup confirmation behavior applies.
     *
     * @param tenantDomain Tenant domain.
     * @return true if the compatibility setting allows skipping, false otherwise.
     */
    private boolean isSkipSignupConfirmationEnabledByCompatibilitySetting(String tenantDomain) {

        CompatibilitySettingsService compatibilitySettingsService =
                EventHookHandlerDataHolder.getInstance().getCompatibilitySettingsService();
        try {
            CompatibilitySetting setting = compatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(
                    tenantDomain,
                    Constants.REGISTRATION_COMPAT_SETTING_GROUP,
                    Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING);
            String value = setting.getCompatibilitySetting(Constants.REGISTRATION_COMPAT_SETTING_GROUP)
                    .getSettingValue(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING);
            return Boolean.parseBoolean(value);
        } catch (Exception e) {
            log.warn("Error while reading compatibility setting for skip signup confirmation. " +
                    "Defaulting to skip enabled.", e);
            return false;
        }
    }

    private EventMetadata getEventMetadata(String eventProfile, Event event) {

        String eventName = null;
        String channel = null;
        if (isUserRegistrationSuccessFlow(event)) {
            channel = REGISTRATION_CHANNEL;
            eventName = POST_REGISTRATION_SUCCESS_EVENT;
        } else if (isUserRegistrationFailedFlow(event.getEventName())) {
            channel = REGISTRATION_CHANNEL;
            eventName = POST_REGISTRATION_FAILED_EVENT;
        }
        EventMetadata eventMetadata = EventMetadata.builder()
                .event(String.valueOf(eventName))
                .channel(String.valueOf(channel))
                .eventProfile(WSO2.name())
                .build();
        if (eventMetadata != null && eventProfile.equals(eventMetadata.getEventProfile())) {
            return eventMetadata;
        }
        return null;
    }

    private void publishRegistrationEvent(String tenantDomain, Channel registrationChannel, String eventUri,
                                          String eventProfileName, RegistrationEventPayloadBuilder payloadBuilder,
                                          EventData eventData, Event event)
            throws IdentityEventException, EventPublisherException {

        EventContext eventContext = EventContext.builder()
                .tenantDomain(tenantDomain)
                .eventUri(registrationChannel.getUri())
                .eventProfileName(eventProfileName)
                .eventProfileVersion(EVENT_PROFILE_VERSION)
                .build();

        if (!EventHookHandlerDataHolder.getInstance().getEventPublisherService().canHandleEvent(eventContext)) {
            return;
        }

        EventPayload eventPayload;
        if (isUserRegistrationSuccessFlow(event)) {
            eventPayload = payloadBuilder.buildRegistrationSuccessEvent(eventData);
        } else if (isUserRegistrationFailedFlow(event.getEventName())) {
            eventPayload = payloadBuilder.buildRegistrationFailureEvent(eventData);
        } else {
            throw new IdentityRuntimeException("Unsupported event type: " + event.getEventName());
        }

        SecurityEventTokenPayload securityEventTokenPayload =
                EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }
}
