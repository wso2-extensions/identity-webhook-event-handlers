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

package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ApplicationBasicInfo;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.MinimalOrganization;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenIssuedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.AccessToken;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Builder class for creating WSO2 Token Event Payloads.
 */
public class WSO2TokenEventPayloadBuilder implements TokenEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2TokenEventPayloadBuilder.class);

    @Override
    public org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema getEventSchemaType() {

        return org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
    }

    @Override
    public EventPayload buildAccessTokenRevokeEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        UserStore userStore = WSO2PayloadUtils.buildUserStore(eventData);
        List<Application> application = buildApplications(eventData);
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        User user = WSO2PayloadUtils.buildUser(eventData);
        if (user != null) {
            user.setOrganization(organization);
        }

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);

        return new WSO2TokenRevokedEventPayload.Builder()
                .initiatorType(initiatorType)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .user(user)
                .applications(application)
                .action(action)
                .build();
    }

    @Override
    public EventPayload buildAccessTokenIssueEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        UserStore userStore = WSO2PayloadUtils.buildUserStore(eventData);
        Application application = buildApplication(eventData);
        AccessToken accessToken = buildAccessToken(eventData);
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());

        User user = null;
        if (accessToken != null && WSO2PayloadUtils.isUserBasedGrantType(accessToken.getGrantType())) {
            user = new User();
            WSO2PayloadUtils.populateUserIdAndRef(user, eventData.getUserId());

            boolean isOrganizationUser = isOrganizationUser(eventData);

            if (isOrganizationUser) {
                String userResidentOrganizationId = getUserResidentOrganizationIdForOrgUser(eventData);
                String userResidentTenantDomain = resolveUserResidentTenantDomain(userResidentOrganizationId);
                Organization userResidentOrganization =
                        buildUserResidentOrganizationForOrgUser(userResidentOrganizationId, userResidentTenantDomain);

                WSO2PayloadUtils.populateUserClaims(user, eventData.getUserId(), userResidentTenantDomain);
                user.setOrganization(userResidentOrganization);
            } else {
                WSO2PayloadUtils.populateUserClaims(user, eventData.getUserId(), eventData.getTenantDomain());
                user.setOrganization(organization);
            }
        }

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);

        return new WSO2TokenIssuedEventPayload.Builder()
                .initiatorType(initiatorType)
                .accessToken(accessToken)
                .application(application)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .action(action)
                .build();
    }

    private AccessToken buildAccessToken(EventData eventData) {

        if (eventData == null) {
            return null;
        }
        Map<String, Object> properties = eventData.getProperties();

        String iat = String.valueOf(properties.get(IdentityEventConstants.EventProperty.IAT));
        String tokenType = (String) properties.get(IdentityEventConstants.EventProperty.TOKEN_TYPE);
        String grantType = (String) properties.get(IdentityEventConstants.EventProperty.GRANT_TYPE);
        String jti = (String) properties.get(IdentityEventConstants.EventProperty.JTI);

        if (StringUtils.isNotBlank(iat) && StringUtils.isNotBlank(tokenType)) {
            return new AccessToken.Builder()
                    .tokenType(tokenType)
                    .grantType(grantType)
                    .iat(iat)
                    .jti(jti)
                    .build();
        }
        return null;
    }

    private Application buildApplication(EventData eventData) {

        if (eventData == null) {
            return null;
        }
        Map<String, Object> properties = eventData.getProperties();

        String applicationName = (String) properties.get(IdentityEventConstants.EventProperty.APPLICATION_NAME);
        String consumerKey = (String) properties.get(IdentityEventConstants.EventProperty.CONSUMER_KEY);

        if (StringUtils.isNotBlank(applicationName)) {
            return new Application.Builder()
                    .name(applicationName)
                    .consumerKey(consumerKey)
                    .build();
        }
        return null;
    }

    private List<Application> buildApplications(EventData eventData) {

        if (eventData == null) {
            return null;
        }
        Map<String, Object> properties = eventData.getProperties();

        if (properties.get(IdentityEventConstants.EventProperty.APPLICATION_ID) != null) {
            String applicationResourceId =
                    String.valueOf(properties.get(IdentityEventConstants.EventProperty.APPLICATION_ID));
            Application application = buildApplicationFromResourceId(eventData, applicationResourceId);
            if (application != null) {
                return List.of(application);
            }
        } else if (properties.get(IdentityEventConstants.EventProperty.CONSUMER_KEYS) instanceof List) {
            return ((List<String>) properties.get(IdentityEventConstants.EventProperty.CONSUMER_KEYS)).stream()
                    .filter(Objects::nonNull)
                    .filter(consumerKey -> !Constants.CONSOLE_APP_CONSUMER_KEY.equals(consumerKey)) // exclude CONSOLE
                    .map(consumerKey -> buildApplicationFromConsumerKey(eventData, consumerKey))
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());
        }
        return null;
    }

    private Application buildApplicationFromConsumerKey(EventData eventData, String consumerKey) {

        if (eventData == null || StringUtils.isBlank(consumerKey)) {
            return null;
        }

        try {
            ServiceProvider serviceProvider =
                    WSO2EventHookHandlerDataHolder.getInstance().getApplicationManagementService()
                            .getServiceProviderByClientId(consumerKey, "oauth2", eventData.getTenantDomain());
            if (serviceProvider != null) {
                return new Application.Builder()
                        .id(serviceProvider.getApplicationResourceId())
                        .name(serviceProvider.getApplicationName())
                        .consumerKey(consumerKey)
                        .build();
            }
        } catch (IdentityApplicationManagementException e) {
            LOG.debug("Error while retrieving application by consumer key: " + consumerKey, e);
        }
        return null;
    }

    private Application buildApplicationFromResourceId(EventData eventData, String resourceId) {

        if (eventData == null || StringUtils.isBlank(resourceId)) {
            return null;
        }

        try {
            ApplicationBasicInfo applicationBasicInfo =
                    WSO2EventHookHandlerDataHolder.getInstance().getApplicationManagementService()
                            .getApplicationBasicInfoByResourceId(resourceId, eventData.getTenantDomain());

            if (applicationBasicInfo != null) {
                return new Application.Builder()
                        .id(resourceId)
                        .name(applicationBasicInfo.getApplicationName())
                        .consumerKey(applicationBasicInfo.getClientId())
                        .build();
            }
        } catch (IdentityApplicationManagementException e) {
            LOG.debug("Error while retrieving application by resource Id: " + resourceId, e);
        }
        return null;
    }

    private String resolveUserResidentTenantDomain(String userResidentOrganizationId) {

        if (StringUtils.isBlank(userResidentOrganizationId)) {
            return null;
        }

        try {
            return WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                    .resolveTenantDomain(userResidentOrganizationId);
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving tenant domain for user resident organization: " +
                    userResidentOrganizationId, e);
        }
        return null;
    }

    private Organization buildUserResidentOrganizationForOrgUser(String userResidentOrganizationId,
                                                                 String userResidentTenantDomain) {

        if (StringUtils.isBlank(userResidentOrganizationId) || StringUtils.isBlank(userResidentTenantDomain)) {
            return null;
        }

        try {
            MinimalOrganization userResidentOrganization =
                    WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager()
                            .getMinimalOrganization(userResidentOrganizationId, userResidentTenantDomain);
            if (userResidentOrganization != null) {
                return new Organization(userResidentOrganization.getId(),
                        userResidentOrganization.getName(),
                        userResidentOrganization.getOrganizationHandle(),
                        userResidentOrganization.getDepth());
            }
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving retrieving user resident organization: " +
                    userResidentOrganizationId, e);
        }
        LOG.debug("No organization found for the given organization id: " + userResidentOrganizationId);
        return null;
    }

    private boolean isOrganizationUser(EventData eventData) {

        return Boolean.parseBoolean(String.valueOf(
                eventData.getProperties().get(IdentityEventConstants.EventProperty.IS_ORGANIZATION_USER)));
    }

    private String getUserResidentOrganizationIdForOrgUser(EventData eventData) {

        return eventData.getProperties().get(IdentityEventConstants.EventProperty.USER_RESIDENT_ORGANIZATION_ID) !=
                null ?
                String.valueOf(eventData.getProperties()
                        .get(IdentityEventConstants.EventProperty.USER_RESIDENT_ORGANIZATION_ID)) : null;
    }
}
