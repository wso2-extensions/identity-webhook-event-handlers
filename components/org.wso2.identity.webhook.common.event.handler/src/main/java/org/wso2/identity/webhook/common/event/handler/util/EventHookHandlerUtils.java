/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.util;

import com.wso2.identity.asgardeo.event.configuration.mgt.core.service.exception.EventConfigurationMgtServerException;
import com.wso2.identity.asgardeo.event.configuration.mgt.core.service.model.ResourceConfig;
import com.wso2.identity.asgardeo.event.configuration.mgt.core.service.util.EventConfigurationMgtUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.wso2.identity.asgardeo.event.configuration.mgt.core.service.util.EventConfigurationMgtConstants.EVENT_CONFIG_SCHEMA_NAME_KEY;
import static com.wso2.identity.asgardeo.event.configuration.mgt.core.service.util.EventConfigurationMgtConstants.ErrorMessages.ERROR_WHILE_CASTING_EVENT_CONFIG_AT_SERVER;
import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.CORRELATION_ID_MDC;

/**
 * This class contains the utility method implementations.
 */
public class EventHookHandlerUtils {

    private static final Log log = LogFactory.getLog(EventHookHandlerUtils.class);

    /**
     * Retrieve event uri.
     *
     * @param eventKey  Event key.
     * @return Event uri string.
     * @throws IdentityEventServerException If an error occurs.
     */
    public static String getEventUri(String eventKey) throws IdentityEventServerException {

        try {
            ResourceConfig eventConfigObject = EventConfigurationMgtUtils.getEventConfig(eventKey);
            if (eventConfigObject.getConfigs() != null &&
                    eventConfigObject.getConfigs().containsKey(EVENT_CONFIG_SCHEMA_NAME_KEY)) {
                return (String) eventConfigObject.getConfigs().get(EVENT_CONFIG_SCHEMA_NAME_KEY);
            } else {
                throw new IdentityEventServerException("Event schema not found in the resource event config " +
                        "for the eventKey: " + eventKey);
            }
        } catch (EventConfigurationMgtServerException e) {
            throw new IdentityEventServerException(e.getErrorCode(), e.getMessage());
        } catch (ClassCastException e) {
            throw new IdentityEventServerException(ERROR_WHILE_CASTING_EVENT_CONFIG_AT_SERVER.getCode(),
                    ERROR_WHILE_CASTING_EVENT_CONFIG_AT_SERVER.getMessage());
        }
    }

    /**
     * Retrieve the audience.
     *
     * @param eventUri     Event URI.
     * @param tenantDomain Tenant domain.
     * @return Audience string.
     */
    public static SecurityEventTokenPayload buildSecurityEventToken(EventPayload eventPayload,
                                                                    AuthenticationContext context, String eventUri,
                                                                    String tenantDomain)
            throws IdentityEventException {

        if (eventPayload == null) {
            throw new IdentityEventException("Invalid event payload input: Event payload input cannot be null.");
        }

        if (StringUtils.isEmpty(eventUri)) {
            throw new IdentityEventException("Invalid event URI input: Event URI input cannot be null or empty.");
        }

        SecurityEventTokenPayload securityEventTokenPayload = new SecurityEventTokenPayload();
        securityEventTokenPayload.setIss(getReference(tenantDomain, "", ""));
        securityEventTokenPayload.setIat(System.currentTimeMillis());
        securityEventTokenPayload.setJti(context.getContextIdentifier());
        securityEventTokenPayload.setTxn(getCorrelationID());
        Map<String, EventPayload> eventMap = new HashMap<>();
        eventMap.put(eventUri, eventPayload);
        securityEventTokenPayload.setEvent(eventMap);
        return securityEventTokenPayload;
    }

    /**
     * Get correlation id from the MDC.
     * If not then generate a random UUID, add it to MDC and return the UUID.
     *
     * @return Correlation id
     */
    public static String getCorrelationID() {

        String correlationID = MDC.get(CORRELATION_ID_MDC);
        if (StringUtils.isBlank(correlationID)) {
            correlationID = UUID.randomUUID().toString();
            MDC.put(CORRELATION_ID_MDC, correlationID);
        }
        return correlationID;
    }

    /**
     * Get the authenticated user from the event.
     *
     * @param event Event.
     * @return AuthenticatedUser.
     */
    public static AuthenticatedUser getAuthenticatedUserFromEvent(Event event) {

        Map<String, Object> params = (Map<String, Object>) event.getEventProperties().get("params");
        Object userObj = params.get("user");

        if (userObj instanceof AuthenticatedUser) {
            return (AuthenticatedUser)userObj;
        }
        return null;
    }

    public static AuthenticatedUser setLocalUserClaims(AuthenticatedUser authenticatedUser,
                                                       AuthenticationContext context) {
        try {
            // Retrieve the claim mappings from the context
            Map<String, String> claimMappings = (Map<String, String>) context.getParameters()
                    .get(Constants.SP_TO_CARBON_CLAIM_MAPPING);

            if (claimMappings == null) {
                log.error("No claim mappings found in the context.");
                return authenticatedUser;
            }

            // Get the user attributes from the authenticated user
            Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();

            // If user attributes are null, initialize them
            if (userAttributes == null) {
                userAttributes = new HashMap<>();
            }

            for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {

                ClaimMapping claimMapping = entry.getKey();
                Claim localClaim = claimMapping.getLocalClaim();

                // Check if the claim mapping is already present in the claim mappings
                if (claimMappings.containsKey(localClaim.getClaimUri())) {
                    // Update the user attributes with the new claim mapping
                    localClaim.setClaimUri(claimMappings.get(localClaim.getClaimUri()));
                }
            }
        } catch (Exception e) {
            log.error("Error occurred while setting user claims.", e);
        }

        return authenticatedUser;
    }

    /**
     * Retrieve the reference for the given endpoint and id.
     *
     * @param tenantDomain Tenant Domain.
     * @param endpoint     Endpoint.
     * @param id           Resource id.
     * @return Resource location.
     */
    public static String getReference(String tenantDomain, String endpoint, String id) {

        StringBuilder reference = new StringBuilder(getURL(tenantDomain, endpoint))
                .append(id);
        return reference.toString();
    }

    private static String getURL(String tenantDomain, String endpoint) {

        String url;
        try {
            if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
                url = ServiceURLBuilder.create().addPath(endpoint).build().getAbsolutePublicURL();
            } else {
                String serverUrl = ServiceURLBuilder.create().build().getAbsolutePublicURL();
                if (isNotASuperTenantFlow(tenantDomain)) {
                    url = serverUrl + Constants.TENANT_SEPARATOR + tenantDomain + endpoint;
                } else {
                    url = serverUrl + endpoint;
                }
            }
            return url;
        } catch (URLBuilderException e) {
            logDebug(log, "Error occurred while building the endpoint URL with tenant " +
                        "qualified URL.", e);
            // Fallback to legacy approach during error scenarios to maintain backward compatibility.
            return getURLLegacy(tenantDomain, endpoint);
        }
    }

    private static String getURLLegacy(String tenantDomain, String endpoint) {

        String url;
        if (isNotASuperTenantFlow(tenantDomain)) {
            url = IdentityUtil.getServerURL(Constants.TENANT_SEPARATOR +
                    tenantDomain + endpoint, true, true);
        } else {
            url = IdentityUtil.getServerURL(endpoint, true, true);
        }
        return url;
    }

    private static boolean isNotASuperTenantFlow(String tenantDomain) {

        return !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain);
    }

    public static void logDebug(Log log, String message) {

        if (log.isDebugEnabled()) {
            log.debug(message);
        }
    }

    public static void logDebug(Log log, String message, Exception e) {

        if (log.isDebugEnabled()) {
            log.debug(message, e);
        }
    }

    public static void logError(Log log, String message, Exception e) {

        log.error(message, e);
    }
}
