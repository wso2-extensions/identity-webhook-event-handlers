package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils.getUserResidentOrganization;

public class WSO2SessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    Log log = LogFactory.getLog(WSO2SessionEventPayloadBuilder.class);

    @Override
    public EventPayload buildSessionTerminateEvent(EventData eventData) throws IdentityEventException {
        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new IdentityEventException("Authenticated user cannot be null.");
        }

        User user = new User();
        WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);

        Organization tenant = new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain())),
                authenticationContext.getTenantDomain());
        UserStore userStore = null;
        if (authenticatedUser.getUserStoreDomain() != null) {
            userStore = new UserStore(authenticatedUser.getUserStoreDomain());
        }
        Organization b2bUserResidentOrganization = null;
        if (authenticatedUser.getUserResidentOrganization() != null) {
            b2bUserResidentOrganization = getUserResidentOrganization(
                    authenticatedUser.getUserResidentOrganization());
        }

        List<Application> applications = new ArrayList<>();

        Application application = new Application(
                authenticationContext.getServiceProviderResourceId(),
                authenticationContext.getServiceProviderName());
        applications.add(application);

        String sessionId = extractSessionId(eventData);

        return new WSO2SessionRevokedEventPayload.Builder()
                .user(user)
                .tenant(tenant)
                .userResidentOrganization(b2bUserResidentOrganization)
                .userStore(userStore)
                .sessionId(sessionId)
                .initiatorType(null)
                .applications(applications)
                .build();

    }

    @Override
    public EventPayload buildSessionCreateEvent(EventData eventData) throws IdentityEventException {
        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new IdentityEventException("Authenticated user cannot be null.");
        }

        User user = new User();
        WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);

        Organization tenant = new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain())),
                authenticationContext.getTenantDomain());
        UserStore userStore = null;
        if (authenticatedUser.getUserStoreDomain() != null) {
            userStore = new UserStore(authenticatedUser.getUserStoreDomain());
        }
        Organization b2bUserResidentOrganization = null;
        if (authenticatedUser.getUserResidentOrganization() != null) {
            b2bUserResidentOrganization = getUserResidentOrganization(
                    authenticatedUser.getUserResidentOrganization());
        }

        String sessionId = extractSessionId(eventData);

        Application application = new Application(
                authenticationContext.getServiceProviderResourceId(),
                authenticationContext.getServiceProviderName());

        return new WSO2SessionCreatedEventPayload.Builder()
                .sessionId(sessionId)
                .currentAcr(authenticationContext.getSelectedAcr())
                .user(user)
                .tenant(tenant)
                .userResidentOrganization(b2bUserResidentOrganization)
                .userStore(userStore)
                .application(application)
                .build();
    }

    @Override
    public EventPayload buildSessionUpdateEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventPayload buildSessionExpireEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventPayload buildSessionExtendEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    private static String extractSessionId(EventData eventData) {

        if (eventData.getEventParams().containsKey(Constants.SESSION_ID) &&
                eventData.getEventParams().get(Constants.SESSION_ID) != null) {
            return eventData.getEventParams().get(Constants.SESSION_ID).toString();
        } else if (eventData.getAuthenticationContext() != null) {
            return eventData.getAuthenticationContext().getSessionIdentifier();
        }
        return null;
    }

    @Override
    public EventSchema getEventSchemaType() {

        return EventSchema.WSO2;
    }
}
