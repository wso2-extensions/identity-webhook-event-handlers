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
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.model.EventData;

import javax.servlet.http.HttpServletRequest;
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
     * Build the event data provider.
     *
     * @param event Event object.
     * @return Event data object.
     */
    public static EventData buildEventDataProvider(Event event) {

        Map<String, Object> properties = event.getEventProperties();
        Map<String, Object> params = (Map)properties.get("params");
        AuthenticationContext context = (AuthenticationContext)properties.get("context");
        Object user = params.get("user");
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        // User information in login failed events.
        User loginIdentifier = new User();
        if (user instanceof AuthenticatedUser){
            authenticatedUser = (AuthenticatedUser)user;
            setLocalUserClaimsToAuthenticatedUser(authenticatedUser, context);
        } else {
            loginIdentifier = (User)user;
        }

        return EventData.builder()
                .eventName(event.getEventName())
                .request((HttpServletRequest)properties.get("request"))
                .eventParams(params)
                .authenticationContext((AuthenticationContext)properties.get("context"))
                .authenticatorStatus((AuthenticatorStatus)properties.get("authenticationStatus"))
                .authenticatedUser(authenticatedUser)
                .loginIdentifier(loginIdentifier)
                .build();
    }

    /**
     * Retrieve the audience.
     *
     * @param eventUri     Event URI.
     * @return Audience string.
     */
    public static SecurityEventTokenPayload buildSecurityEventToken(EventPayload eventPayload,
                                                                    AuthenticationContext context, String eventUri)
            throws IdentityEventException {

        if (eventPayload == null) {
            throw new IdentityEventException("Invalid event payload input: Event payload input cannot be null.");
        }

        if (StringUtils.isEmpty(eventUri)) {
            throw new IdentityEventException("Invalid event URI input: Event URI input cannot be null or empty.");
        }

        SecurityEventTokenPayload securityEventTokenPayload = new SecurityEventTokenPayload();
        securityEventTokenPayload.setIss(getReference("", ""));
        securityEventTokenPayload.setIat(System.currentTimeMillis());
        securityEventTokenPayload.setJti(UUID.randomUUID().toString());
        securityEventTokenPayload.setTxn(context.getContextIdentifier());
        securityEventTokenPayload.setRci(getCorrelationID());
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
     * Retrieve the reference for the given endpoint and id.
     *
     * @param endpoint     Endpoint.
     * @param id           Resource id.
     * @return Resource location.
     */
    public static String getReference(String endpoint, String id) {

        return getURL(endpoint) + "/" + id;
    }

    private static String getURL(String endpoint) {

        try {
            return ServiceURLBuilder.create().addPath(endpoint).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            log.debug("Error occurred while building the endpoint URL with tenant " +
                        "qualified URL.", e);
        }
        return endpoint;
    }

    /**
     * Publish the event payload.
     *
     * @param securityEventTokenPayload Security event token payload.
     * @param tenantDomain              Tenant domain.
     * @param eventUri                  Event URI.
     * @throws IdentityEventException If an error occurs.
     */
    public static void publishEventPayload(SecurityEventTokenPayload securityEventTokenPayload, String tenantDomain,
                                     String eventUri) throws IdentityEventException {

        try {
            EventContext eventContext = EventContext.builder()
                    .tenantDomain(tenantDomain)
                    .eventUri(eventUri)
                    .build();
            EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                    .publish(securityEventTokenPayload, eventContext);
        } catch (Exception e) {
            throw new IdentityEventException(String.format("Error while handling %s event.",
                    eventUri), e);
        }
    }
}
