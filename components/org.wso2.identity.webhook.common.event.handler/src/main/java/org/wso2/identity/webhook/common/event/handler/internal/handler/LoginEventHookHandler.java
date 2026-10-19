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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationLoginData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
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
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.CONSOLE_APP_NAME;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.ENHANCED_ORG_LOGIN_ENABLED;

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
            log.debug(eventName + (canHandle ? " event can be handled." : " event cannot be handled."));
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
                log.warn("No event profiles found in the webhook metadata service. Skipping login event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {
                handleEventForProfile(event, eventData, eventProfile);
            }
        } catch (Exception e) {
            log.warn("Error while retrieving login event publisher configuration for tenant.", e);
        }
    }

    private void handleEventForProfile(Event event, EventData eventData, EventProfile eventProfile)
            throws IdentityEventException, EventPublisherException {

        // Prepare schema, payload builder, and event metadata
        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema schema =
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                        eventProfile.getProfile());
        LoginEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getLoginEventPayloadBuilder(schema);

        if (payloadBuilder == null) {
            log.debug("Skipping login event handling for profile " + eventProfile.getProfile());
            return;
        }

        EventMetadata eventMetadata = EventHookHandlerUtils.getEventProfileManagerByProfile(
                eventProfile.getProfile(), event.getEventName());
        if (eventMetadata == null) {
            log.debug("No event metadata found for event: " + event.getEventName() +
                    " in profile: " + eventProfile.getProfile());
            return;
        }

        // Get channel and event URI
        Channel loginChannel = eventProfile.getChannels().stream()
                .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                .findFirst()
                .orElse(null);
        if (loginChannel == null) {
            log.debug("No channel found for login event profile: " + eventProfile.getProfile());
            return;
        }

        String eventUri = loginChannel.getEvents().stream()
                .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(), channelEvent.getEventUri()))
                .findFirst()
                .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                .orElse(null);

        // Skip system application events
        String applicationNameInEvent = eventData.getAuthenticationContext().getServiceProviderName();
        boolean isEventTriggeredForSystemApplication = StringUtils.isNotBlank(applicationNameInEvent)
                && CONSOLE_APP_NAME.equals(applicationNameInEvent);
        if (isEventTriggeredForSystemApplication) {
            log.debug("Event trigger for system application: " + applicationNameInEvent +
                    ". Skipping event handling for login event profile: " + eventProfile.getProfile());
            return;
        }

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        /*
         A login to an application shared with a sub organization raises this event twice: once in the sub
         organization the user authenticated in, and once in the organization that owns the application. Only the
         second one is published, because it is the one that can resolve the application and its owner. The
         organization the user came from is read off that event rather than carried over from the first: the two
         are separate requests on separate threads, so nothing stored on the first survives, and a login that never
         reaches the second would leave the value behind for an unrelated one.
         */
        if (isSubOrganizationLoginOfSharedApplication(authenticationContext)) {
            if (log.isDebugEnabled()) {
                log.debug("Login event is raised in the sub organization of a shared application login, " +
                        "which is not published from there. Skipping login event profile: " +
                        eventProfile.getProfile());
            }
            return;
        }
        /*
         The resolved tenant replaces the one the event data was built with, so that the payload is built for the
         same organization the event is published to.
         */
        EventData publishingEventData = eventData.toBuilder()
                .tenantDomain(resolvePublishingTenantDomain(eventData))
                .build();
        publishEvent(publishingEventData.getTenantDomain(), loginChannel, eventUri,
                eventProfile.getProfile(), payloadBuilder, publishingEventData, event.getEventName());
    }

    /**
     * Whether this login is the one performed in the sub organization a user authenticated in, for a login to
     * an application shared from an ancestor organization.
     * <p>
     * No login event is published from the sub organization on that flow. A successful login is published from
     * the organization that owns the application, which is the one that can resolve the application and its
     * owner. A failed login never reaches that organization, so it is not published at all: in this mode only
     * the success event is wanted.
     * <p>
     * The enhanced organization login flag is set only for a shared application, and only its legacy value marks
     * this flow.
     *
     * @param authenticationContext Context of the login.
     * @return true if the login belongs to the sub organization side of such a login.
     */
    private boolean isSubOrganizationLoginOfSharedApplication(AuthenticationContext authenticationContext) {

        Object enhancedOrgLoginEnabled = authenticationContext.getProperties().get(ENHANCED_ORG_LOGIN_ENABLED);
        if (enhancedOrgLoginEnabled == null || Boolean.TRUE.equals(enhancedOrgLoginEnabled)) {
            // Absent: the application is not shared, so this is not that flow. True: the enhanced flow publishes
            // from the organization the user authenticated in. Either way every other login, a login of a root
            // organization included, is left untouched by what follows.
            return false;
        }
        try {
            return OrganizationManagementUtil.isOrganization(authenticationContext.getLoginTenantDomain());
        } catch (OrganizationManagementException e) {
            log.warn("Error while checking whether the login tenant is an organization.", e);
            return false;
        }
    }

    /**
     * Tenant the login event is published to.
     * <p>
     * For a login that came through another organization this is the organization the user authenticated in. The
     * context states it in one of three ways, depending on the flow: as the accessing organization of the login,
     * as the resident organization of the authenticated user, or as the organization of the user authenticated by
     * the organization authenticator. For every other login it is the tenant the login was performed in.
     *
     * @param eventData Data of the login event.
     * @return Tenant domain to publish the event to.
     */
    private String resolvePublishingTenantDomain(EventData eventData) {

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        if (log.isDebugEnabled()) {
            log.debug("Resolving the tenant to publish the login event to. Login tenant: " +
                    authenticationContext.getLoginTenantDomain() +
                    ", accessing organization: " + resolveAccessingOrganizationTenantDomain(authenticationContext) +
                    ", authenticated user organization: " +
                    resolveUserOrganizationTenantDomain(eventData.getAuthenticatedUser()) +
                    ", organization authenticator user organization: " +
                    resolveOrganizationAuthenticatorUserTenantDomain(authenticationContext));
        }
        String tenantDomain = resolveAccessingOrganizationTenantDomain(authenticationContext);
        if (StringUtils.isNotBlank(tenantDomain)) {
            return tenantDomain;
        }
        tenantDomain = resolveUserOrganizationTenantDomain(eventData.getAuthenticatedUser());
        if (StringUtils.isNotBlank(tenantDomain)) {
            return tenantDomain;
        }
        tenantDomain = resolveOrganizationAuthenticatorUserTenantDomain(authenticationContext);
        if (StringUtils.isNotBlank(tenantDomain)) {
            return tenantDomain;
        }
        return authenticationContext.getLoginTenantDomain();
    }

    /**
     * Organization the login is accessing, as the shared application login flow records it.
     */
    private String resolveAccessingOrganizationTenantDomain(AuthenticationContext authenticationContext) {

        OrganizationLoginData organizationLoginData = authenticationContext.getOrganizationLoginData();
        if (organizationLoginData == null || organizationLoginData.getAccessingOrganization() == null) {
            return null;
        }
        return organizationLoginData.getAccessingOrganization().getHandle();
    }

    /**
     * Organization a user resides in. The resident organization is preferred over the tenant of the user, which on
     * some flows is the tenant of the application rather than of the user.
     */
    private String resolveUserOrganizationTenantDomain(AuthenticatedUser authenticatedUser) {

        if (authenticatedUser == null) {
            return null;
        }
        String organizationId = StringUtils.isNotBlank(authenticatedUser.getUserResidentOrganization())
                ? authenticatedUser.getUserResidentOrganization() : authenticatedUser.getAccessingOrganization();
        if (StringUtils.isNotBlank(organizationId)) {
            try {
                return EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                        .resolveTenantDomain(organizationId);
            } catch (OrganizationManagementException e) {
                log.warn("Error while resolving the tenant of organization: " + organizationId, e);
            }
        }
        return resolveTenantDomainIfOrganization(authenticatedUser.getTenantDomain());
    }

    /**
     * Organization of the user the organization authenticator authenticated. On a login that federates to another
     * organization, that authenticator's own authenticated user is the one who resides there, even when the
     * subject of the context is not set.
     */
    private String resolveOrganizationAuthenticatorUserTenantDomain(AuthenticationContext authenticationContext) {

        Map<String, AuthenticatedIdPData> authenticatedIdPs = authenticationContext.getCurrentAuthenticatedIdPs();
        if (authenticatedIdPs == null) {
            return null;
        }
        for (AuthenticatedIdPData authenticatedIdPData : authenticatedIdPs.values()) {
            if (authenticatedIdPData.getAuthenticators() == null || authenticatedIdPData.getUser() == null) {
                continue;
            }
            boolean authenticatedByOrganizationAuthenticator = authenticatedIdPData.getAuthenticators().stream()
                    .anyMatch(authenticator ->
                            FrameworkConstants.ORGANIZATION_AUTHENTICATOR.equals(authenticator.getName()));
            if (!authenticatedByOrganizationAuthenticator) {
                continue;
            }
            String tenantDomain = resolveUserOrganizationTenantDomain(authenticatedIdPData.getUser());
            if (StringUtils.isNotBlank(tenantDomain)) {
                return tenantDomain;
            }
        }
        return null;
    }

    /**
     * The given tenant, but only when it is a sub organization. A root tenant is no answer here: it is what the
     * caller falls back to anyway.
     */
    private String resolveTenantDomainIfOrganization(String tenantDomain) {

        if (StringUtils.isBlank(tenantDomain)) {
            return null;
        }
        try {
            return OrganizationManagementUtil.isOrganization(tenantDomain) ? tenantDomain : null;
        } catch (OrganizationManagementException e) {
            log.warn("Error while checking whether tenant: " + tenantDomain + " is an organization.", e);
            return null;
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
