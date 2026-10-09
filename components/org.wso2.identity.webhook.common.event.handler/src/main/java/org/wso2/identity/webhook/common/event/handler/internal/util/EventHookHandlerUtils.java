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

package org.wso2.identity.webhook.common.event.handler.internal.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.model.common.ComplexSubject;
import org.wso2.carbon.identity.event.publisher.api.model.common.SimpleSubject;
import org.wso2.carbon.identity.event.publisher.api.model.common.Subject;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.api.service.EventProfileManager;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.CORRELATION_ID_MDC;

/**
 * Utility class for Event Handler Hooks.
 */
public class EventHookHandlerUtils {

    private static final Log log = LogFactory.getLog(EventHookHandlerUtils.class);

    private EventHookHandlerUtils() {

    }

    /**
     * Build the event data provider.
     *
     * @param event Event object.
     * @return Event data object.
     */
    public static EventData buildEventDataProvider(Event event) throws IdentityEventException {

        Map<String, Object> properties = validateAndGetProperties(event);

        Map<String, Object> params = extractParams(properties);
        AuthenticationContext authenticationContext = extractAuthenticationContext(properties);
        SessionContext sessionContext = extractSessionContext(properties);
        AuthenticatorStatus status = extractAuthenticatorStatus(properties);
        HttpServletRequest request = extractRequest(properties);

        String tenantDomain = resolveTenantDomain(authenticationContext, params, properties);

        AuthenticatedUser authenticatedUser = extractAuthenticatedUser(params, authenticationContext, sessionContext);
        String userId = resolveUserId(authenticatedUser, properties, tenantDomain);

        return EventData.builder()
                .eventName(event.getEventName())
                .request(request)
                .eventParams(params)
                .authenticationContext(authenticationContext)
                .authenticatorStatus(status)
                .authenticatedUser(authenticatedUser)
                .sessionContext(sessionContext)
                .userId(userId)
                .tenantDomain(tenantDomain)
                .properties(properties)
                .build();
    }

    /**
     * Retrieve the audience.
     *
     * @param eventPayload
     * @param eventUri     Event URI.
     * @return Audience string.
     */
    public static SecurityEventTokenPayload buildSecurityEventToken(EventPayload eventPayload, String eventUri)
            throws IdentityEventException {

        return buildSecurityEventToken(eventPayload, eventUri, null, null);
    }

    /**
     * Retrieve the audience.
     *
     * @param eventUri Event URI.
     * @return Audience string.
     */
    public static SecurityEventTokenPayload buildSecurityEventToken(EventPayload eventPayload, String eventUri,
                                                                    EventData eventData, EventSchema schema)
            throws IdentityEventException {

        if (eventPayload == null) {
            throw new IdentityEventException("Invalid event payload input: Event payload input cannot be null.");
        }

        if (StringUtils.isEmpty(eventUri)) {
            throw new IdentityEventException("Invalid event URI input: Event URI input cannot be null or empty.");
        }

        Map<String, EventPayload> eventMap = new HashMap<>();
        eventMap.put(eventUri, eventPayload);

        Subject subId = null;
        long iat = System.currentTimeMillis();
        if (EventSchema.CAEP.equals(schema)) {
            subId = extractSubjectFromEventData(eventData);
            // JWT iat (RFC 7519 NumericDate) and CAEP's event_timestamp both require epoch seconds.
            iat = iat / 1000;
        }

        return SecurityEventTokenPayload.builder()
                .iss(constructBaseURL())
                .iat(iat)
                .jti(UUID.randomUUID().toString())
                .rci(getCorrelationID())
                .subId(subId)
                .events(eventMap)
                .build();
    }

    /**
     * Get correlation id from the MDC.
     * If not then generate a random UUID, add it to MDC and return the UUID.
     *
     * @return Correlation id
     */
    public static String getCorrelationID() {

        return MDC.get(CORRELATION_ID_MDC);
    }

    /**
     * Get the tenant qualified URL.
     *
     * @return Tenant qualified URL.
     */
    public static String constructBaseURL() {

        try {
            IdentityContext identityContext = IdentityContext.getThreadLocalIdentityContext();
            if (identityContext.getRootOrganization() == null ||
                    StringUtils.isBlank(identityContext.getRootOrganization().getAssociatedTenantDomain())) {
                return null;
            }
            String rootTenantDomain = identityContext.getRootOrganization().getAssociatedTenantDomain();

            if (identityContext.getOrganization() != null && identityContext.getOrganization().getDepth() != 0) {
                String organizationId = identityContext.getOrganization().getId();
                if (StringUtils.isNotBlank(organizationId)) {
                    log.debug("Resolving root tenant: " + rootTenantDomain +
                            " and organization ID: " + organizationId);
                    return ServiceURLBuilder.create()
                            .addPath("/t/" + rootTenantDomain + "/o/" + organizationId)
                            .build()
                            .getAbsolutePublicURL();
                }
            }

            return ServiceURLBuilder.create()
                    .addPath("/t/" + rootTenantDomain)
                    .build()
                    .getAbsolutePublicURL();

        } catch (URLBuilderException e) {
            log.debug("Error occurred while building the tenant qualified URL.", e);
            return null;
        }
    }

    /**
     * Get the EventMetadata for the given event profile and event name.
     *
     * @param eventProfile Event profile.
     * @param event        Event name.
     * @return EventMetadata if found, otherwise null.
     */
    public static EventMetadata getEventProfileManagerByProfile(String eventProfile, String event) {

        for (EventProfileManager manager : EventHookHandlerDataHolder.getInstance().getEventProfileManagers()) {
            EventMetadata metadata = manager.resolveEventMetadata(event);
            if (metadata != null && eventProfile.equals(metadata.getEventProfile())) {
                return metadata;
            }
        }
        return null;
    }

    // todo: Following methods are CAEP specific. These should move out from this common util.

    /**
     * Extracts the authenticated user from the event data.
     *
     * @param eventData Event data.
     * @return Authenticated user.
     * @throws IdentityEventException If an error occurs while extracting the authenticated user.
     */
    private static AuthenticatedUser extractAuthenticatedUser(EventData eventData) throws IdentityEventException {

        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        try {
            if (authenticatedUser == null) {
                authenticatedUser = (AuthenticatedUser) eventData.getEventParams().
                        get(Constants.EventDataProperties.USER);
            }
            return authenticatedUser;
        } catch (ClassCastException e) {
            throw new IdentityEventException("Error occurred while retrieving authenticated user", e);
        }
    }

    /**
     * Extracts the session ID from the event data.
     *
     * @param eventData Event data.
     * @return Session ID.
     * @throws IdentityEventException If an error occurs while extracting the session ID.
     */
    public static String extractSessionId(EventData eventData) {

        if (eventData.getEventParams().containsKey(Constants.EventDataProperties.SESSION_ID) &&
                eventData.getEventParams().get(Constants.EventDataProperties.SESSION_ID) != null) {
            return eventData.getEventParams().get(Constants.EventDataProperties.SESSION_ID).toString();
        } else if (eventData.getAuthenticationContext() != null) {
            return eventData.getAuthenticationContext().getSessionIdentifier();
        }
        return null;
    }

    /**
     * Extracts the subject from the event data.
     *
     * @param eventData Event data.
     * @return Subject.
     * @throws IdentityEventException If an error occurs while extracting the subject.
     */
    public static Subject extractSubjectFromEventData(EventData eventData) throws IdentityEventException {

        AuthenticatedUser authenticatedUser = extractAuthenticatedUser(eventData);
        String sessionId = extractSessionId(eventData);

        String userId = eventData.getUserId();
        if (userId == null) {
            log.debug("Unable to resolve user id for the subject; sub_id will be omitted.");
            return null;
        }
        SimpleSubject user = SimpleSubject.createOpaqueSubject(userId);

        String tenantDomain = authenticatedUser != null ? authenticatedUser.getTenantDomain() : eventData.getTenantDomain();
        SimpleSubject tenant = SimpleSubject.createOpaqueSubject(String.valueOf(
                IdentityTenantUtil.getTenantId(tenantDomain)));
        SimpleSubject session = SimpleSubject.createOpaqueSubject(sessionId);

        return ComplexSubject.builder()
                .tenant(tenant)
                .user(user)
                .session(session)
                .build();
    }

    public static Subject buildVerificationSubject(EventData eventData) throws IdentityEventException {

        Map<String, Object> params = eventData.getEventParams();
        String streamId = params.get(Constants.EventDataProperties.STREAM_ID) != null ?
                params.get(Constants.EventDataProperties.STREAM_ID).toString() : null;
        if (streamId == null) {
            throw new IdentityEventException("Stream ID cannot be null");
        }

        return SimpleSubject.createOpaqueSubject(streamId);

    }

    /**
     * Checks if the user is a B2B user based on the authentication context.
     *
     * @param authContext Authentication context.
     * @return True if the user is a B2B user, otherwise false.
     */
    public static boolean isB2BUserLogin(AuthenticationContext authContext) {

        if (authContext == null) {
            return false;
        }

        Map<String, AuthenticatedIdPData> currentIdPs = authContext.getCurrentAuthenticatedIdPs();
        if (currentIdPs == null) {
            return false;
        }

        for (AuthenticatedIdPData idpData : currentIdPs.values()) {
            if (idpData.getAuthenticators() != null) {
                for (AuthenticatorConfig config : idpData.getAuthenticators()) {
                    if (FrameworkConstants.ORGANIZATION_AUTHENTICATOR.equals(config.getName())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static Map<String, Object> validateAndGetProperties(Event event) throws IdentityEventException {

        Map<String, Object> properties = event.getEventProperties();
        if (properties == null) {
            throw new IdentityEventException("Properties cannot be null");
        }
        return properties;
    }

    private static Map<String, Object> extractParams(Map<String, Object> properties) {

        // todo: remove logic that returns properties as parameters and using params field to get properties.
        //  Introduce a separate method to return all properties if event specific properties needs to be handled.

        return properties.containsKey(Constants.EventDataProperties.PARAMS) ?
                (Map<String, Object>) properties.get(Constants.EventDataProperties.PARAMS) : properties;
    }

    private static AuthenticationContext extractAuthenticationContext(Map<String, Object> properties) {

        return properties.containsKey(Constants.EventDataProperties.CONTEXT) ?
                (AuthenticationContext) properties.get(Constants.EventDataProperties.CONTEXT) : null;
    }

    private static AuthenticatorStatus extractAuthenticatorStatus(Map<String, Object> properties) {

        return properties.containsKey(Constants.EventDataProperties.AUTHENTICATION_STATUS) ?
                (AuthenticatorStatus) properties.get(Constants.EventDataProperties.AUTHENTICATION_STATUS) : null;
    }

    private static HttpServletRequest extractRequest(Map<String, Object> params) {

        return params != null ? (HttpServletRequest) params.get(Constants.EventDataProperties.REQUEST) : null;
    }

    private static String resolveTenantDomain(AuthenticationContext context, Map<String, Object> params,
                                              Map<String, Object> properties) {

        if (context != null && StringUtils.isNotBlank(context.getLoginTenantDomain())) {
            return context.getLoginTenantDomain();
        }
        if (properties != null && properties.containsKey(IdentityEventConstants.EventProperty.TENANT_DOMAIN)) {
            return String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));
        }
        return (params != null && params.containsKey(IdentityEventConstants.EventProperty.TENANT_DOMAIN)) ?
                String.valueOf(params.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN)) :
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    private static AuthenticatedUser extractAuthenticatedUser(Map<String, Object> params,
                                                              AuthenticationContext authenticationContext,
                                                              SessionContext sessionContext) {

        if (params != null) {
            Object user = params.get(Constants.EventDataProperties.USER);
            if (user instanceof AuthenticatedUser) {
                AuthenticatedUser authenticatedUser = (AuthenticatedUser) user;
                if (authenticationContext != null) {
                     /* todo: it's not a good practice to modify the authenticated user object.
                      Should remove this code and missing claims should be populated for the user
                      in event in a different way.*/
                    setLocalUserClaimsToAuthenticatedUser(authenticatedUser, authenticationContext);
                }
                return authenticatedUser;
            }
        }

        if (sessionContext != null && sessionContext.getProperties() != null) {
            Object user = sessionContext.getProperties().get(FrameworkConstants.AUTHENTICATED_USER);
            if (user instanceof AuthenticatedUser) {
                return (AuthenticatedUser) user;
            }
        }

        return null;
    }

    /**
     * Resolve the user id via the user store, as a fallback when neither the authenticated
     * user nor a direct USER_ID property is available (e.g. admin-triggered credential changes,
     * where there's no live authenticated session for the target user).
     *
     * @param userName        Username from the event properties.
     * @param userStoreDomain User store domain from the event properties.
     * @param tenantDomain    Tenant domain.
     * @return Resolved user id, or null if it could not be resolved.
     */
    private static String resolveUserIdFromUserStore(String userName, String userStoreDomain, String tenantDomain) {

        if (userName == null || userStoreDomain == null) {
            return null;
        }

        RealmService realmService = EventHookHandlerDataHolder.getInstance().getRealmService();
        if (realmService == null) {
            log.debug("RealmService is not available. Skipping user store based user id resolution.");
            return null;
        }

        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm == null) {
                log.debug("UserRealm is null for tenant: " + tenantDomain);
                return null;
            }

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
                log.debug("UserStoreManager is null for tenant: " + tenantDomain);
                return null;
            }

            String domainQualifiedUserName = userStoreDomain + "/" + userName;
            return userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.USER_ID_CLAIM,
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            log.debug("Error while resolving user id from user store for user: " + userName, e);
            return null;
        }
    }

    private static String resolveUserId(AuthenticatedUser authenticatedUser, Map<String, Object> properties, String tenantDomain) {

        if (authenticatedUser != null) {
            try {
                return authenticatedUser.getUserId();
            } catch (UserIdNotFoundException e) {
                log.debug("User ID not found for the authenticated user: " + authenticatedUser.getUserName());
            }
        }

        if (properties != null && properties.containsKey(IdentityEventConstants.EventProperty.USER_ID)) {
            return (String) properties.get(IdentityEventConstants.EventProperty.USER_ID);
        }
        
        if (properties != null) {
             String userName = (String) properties.get(IdentityEventConstants.EventProperty.USER_NAME);
             String userStoreDomain = (String) properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN);
             return resolveUserIdFromUserStore(userName, userStoreDomain, tenantDomain);
        }
        return null;
    }

    private static SessionContext extractSessionContext(Map<String, Object> properties) {

        return properties.containsKey(Constants.EventDataProperties.SESSION_CONTEXT) ?
                (SessionContext) properties.get(Constants.EventDataProperties.SESSION_CONTEXT) : null;
    }

    private static void setLocalUserClaimsToAuthenticatedUser(AuthenticatedUser authenticatedUser,
                                                              AuthenticationContext context) {

        Map<String, String> claimMappings = (Map<String, String>) context.getParameters()
                .get(Constants.SP_TO_CARBON_CLAIM_MAPPING);

        if (claimMappings == null) {
            log.debug("No local claim mappings found for the authenticated user from the context.");
            return;
        }

        Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();

        if (userAttributes == null) {
            userAttributes = new HashMap<>();
        }

        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {

            ClaimMapping claimMapping = entry.getKey();
            Claim localClaim = claimMapping.getLocalClaim();

            if (claimMappings.containsKey(localClaim.getClaimUri())) {
                localClaim.setClaimUri(claimMappings.get(localClaim.getClaimUri()));
            }
        }
    }

    /**
     * Checks if the event is a sub-organization level event.
     *
     * @return true if the event is a sub-organization level event, false otherwise.
     */
    public static boolean isSubOrgLevel() {

        boolean isSubOrgEvent = false;
        Organization organization = IdentityContext.getThreadLocalIdentityContext().getOrganization();

        if (organization != null && StringUtils.equals(organization.getId(), organization.getParentOrganizationId())) {
            isSubOrgEvent = true;
        }

        return isSubOrgEvent;
    }
}
