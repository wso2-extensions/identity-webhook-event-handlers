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
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.configuration.mgt.core.search.ComplexCondition;
import org.wso2.carbon.identity.configuration.mgt.core.search.Condition;
import org.wso2.carbon.identity.configuration.mgt.core.search.PrimitiveCondition;
import org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType.PrimitiveOperator.EQUALS;

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

        Map<String, Object> properties = event.getEventProperties();
        if (properties == null) {
            throw new IdentityEventException("Properties cannot be null");
        }

        Map<String, Object> params = properties.containsKey(Constants.EventDataProperties.PARAMS) ?
                (Map<String, Object>) properties.get(Constants.EventDataProperties.PARAMS) : null;
        AuthenticationContext context = properties.containsKey(Constants.EventDataProperties.CONTEXT) ?
                (AuthenticationContext) properties.get(Constants.EventDataProperties.CONTEXT) : null;
        AuthenticatorStatus status = properties.containsKey(Constants.EventDataProperties.AUTHENTICATION_STATUS) ?
                (AuthenticatorStatus) properties.get(Constants.EventDataProperties.AUTHENTICATION_STATUS) : null;
        Flow flow = properties.containsKey(Constants.EventDataProperties.FLOW) ?
                (Flow) properties.get(Constants.EventDataProperties.FLOW) : null;
        HttpServletRequest request = params != null ? (HttpServletRequest)
                params.get(Constants.EventDataProperties.REQUEST) : null;

        AuthenticatedUser authenticatedUser = null;
        if (params != null) {
            Object user = params.get(Constants.EventDataProperties.USER);
            if (user instanceof AuthenticatedUser) {
                authenticatedUser = (AuthenticatedUser) user;
                if (context != null) {
                    setLocalUserClaimsToAuthenticatedUser(authenticatedUser, context);
                }
            }
        } else {
            params = properties;
        }

        SessionContext sessionContext = properties.containsKey(Constants.EventDataProperties.SESSION_CONTEXT) ?
                (SessionContext) properties.get(Constants.EventDataProperties.SESSION_CONTEXT) : null;

        return EventData.builder()
                .eventName(event.getEventName())
                .request(request)
                .eventParams(params)
                .authenticationContext(context)
                .authenticatorStatus(status)
                .authenticatedUser(authenticatedUser)
                .sessionContext(sessionContext)
                .flow(flow)
                .build();
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

    /**
     * Returns Event Publisher Configs of the Tenant.
     *
     * @param tenantDomain       Tenant Domain
     * @param eventName          Event Name
     * @param eventConfigManager Event Configuration Manager
     * @throws IdentityEventException if any error occurs
     */
    public static EventPublisherConfig getEventPublisherConfigForTenant
    (String tenantDomain, String eventName, EventConfigManager eventConfigManager) throws IdentityEventException {

        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IdentityEventException("Invalid tenant domain: " + tenantDomain);
        }

        try {
            Condition condition = createPublisherConfigFilterCondition();
            Resources publisherConfigResource = EventHookHandlerDataHolder.getInstance().getConfigurationManager()
                    .getTenantResources(tenantDomain, condition);
            return eventConfigManager.extractEventPublisherConfig(publisherConfigResource, eventName);
        } catch (ConfigurationManagementException | IdentityEventException e) {
            throw new IdentityEventException("Error while retrieving event publisher configuration for tenant.", e);
        }
    }

    /**
     * Helper function for getEventPublisherConfigForTenant.
     */
    private static ComplexCondition createPublisherConfigFilterCondition() {

        List<Condition> conditionList = new ArrayList<>();
        conditionList.add(new PrimitiveCondition(Constants.RESOURCE_TYPE, EQUALS,
                Constants.EVENT_PUBLISHER_CONFIG_RESOURCE_TYPE_NAME));
        conditionList.add(new PrimitiveCondition(Constants.RESOURCE_NAME, EQUALS,
                Constants.EVENT_PUBLISHER_CONFIG_RESOURCE_NAME));
        return new ComplexCondition(ConditionType.ComplexOperator.AND, conditionList);
    }

    /**
     * Resolve the event URI based on the event schema and event name.
     *
     * @param eventSchema Event schema.
     * @param eventName   Event name.
     * @return Event URI.
     */
    public static String resolveEventHandlerKey(EventSchema eventSchema, IdentityEventConstants.EventName eventName) {

        switch (eventSchema) {
            case WSO2:
                switch (eventName) {
                    case AUTHENTICATION_SUCCESS:
                        return Constants.EventHandlerKey.WSO2.LOGIN_SUCCESS_EVENT;
                    case AUTHENTICATION_STEP_FAILURE:
                        return Constants.EventHandlerKey.WSO2.LOGIN_FAILED_EVENT;
                    case USER_SESSION_TERMINATE:
                        return Constants.EventHandlerKey.WSO2.SESSION_REVOKED_EVENT;
                    case SESSION_CREATE:
                        return Constants.EventHandlerKey.WSO2.SESSION_CREATED_EVENT;
                }
                break;
            case CAEP:
                switch (eventName) {
                    case USER_SESSION_TERMINATE:
                        return Constants.EventHandlerKey.CAEP.SESSION_REVOKED_EVENT;
                    case SESSION_CREATE:
                        return Constants.EventHandlerKey.CAEP.SESSION_ESTABLISHED_EVENT;
                    case SESSION_EXTEND:
                    case SESSION_UPDATE:
                        return Constants.EventHandlerKey.CAEP.SESSION_PRESENTED_EVENT;
                    case VERIFICATION:
                        return Constants.EventHandlerKey.CAEP.VERIFICATION_EVENT;
                }
        }
        return null;
    }
}
