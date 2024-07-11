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

package org.wso2.identity.webhook.common.event.handler;

import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.model.AuthStep;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils;
import com.wso2.identity.asgardeo.event.configuration.mgt.core.service.exception.EventConfigurationMgtServerException;
import com.wso2.identity.asgardeo.event.configuration.mgt.core.service.model.EventAttribute;
import com.wso2.identity.asgardeo.event.configuration.mgt.core.service.util.EventConfigurationMgtUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.configuration.mgt.core.search.ComplexCondition;
import org.wso2.carbon.identity.configuration.mgt.core.search.Condition;
import org.wso2.carbon.identity.configuration.mgt.core.search.PrimitiveCondition;
import org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.AnalyticsLoginDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model.AuthenticationData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType.PrimitiveOperator.EQUALS;
import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_SCHEMA_TYPE_WSO2;
import static org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils.logDebug;
import static org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils.logError;

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

        IdentityEventMessageContext identityContext = (IdentityEventMessageContext) messageContext;
        String eventName = identityContext.getEvent().getEventName();

        if (isSupportedEvent(eventName) && isLoginEventHandlerEnabled()) {
            logDebug(log, String.format("canHandle() returning True for the event: %s", eventName));
            return true;
        }
        logDebug(log, "Login Event Handler is not enabled or unsupported event.");
        return false;
    }

    private boolean isSupportedEvent(String eventName) {

        return IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(eventName) ||
                IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(eventName);
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        //TODO: Remove the debug enabled check
        logDebug(log, String.format("Event: %s received.", event.getEventName()));

        AuthenticationContext context = getAuthenticationContext(event);
        if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(event.getEventName())) {
            handleLoginSuccess(event, context);
        } else if (IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(event.getEventName())) {
            handleLoginFailure(event, context);
        }
    }

    private void handleLoginSuccess(Event event, AuthenticationContext context) throws IdentityEventException {

        EventAttribute loginSuccessEventAttribute = getLoginEventPublisherConfigForTenant(
                context.getLoginTenantDomain(), IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        if (loginSuccessEventAttribute.isPublishEnabled()) {
            logDebug(log, String.format("Handling %s event.", event.getEventName()));
            List<AuthStep> authSteps = convertAuthHistoryToAuthSteps(context.getAuthenticationStepHistory());
            handleLoginEvent(event, context, authSteps, true);
        } else {
            logDebug(log, String.format("Event %s received, but ignored as publishing config is disabled", event.getEventName()));
        }
    }

    private void handleLoginFailure(Event event, AuthenticationContext context) throws IdentityEventException {

        EventAttribute eventConfigAttribute = getLoginEventPublisherConfigForTenant(
                context.getLoginTenantDomain(), IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name());
        if (eventConfigAttribute.isPublishEnabled()) {
            logDebug(log, String.format("Handling %s event.", event.getEventName()));
            AuthStep failedStep = setFailedStep(context);
            handleLoginEvent(event, context, new ArrayList<>(Arrays.asList(failedStep)), false);
        } else {
            logDebug(log, String.format("Event %s received, but ignored as publishing config is disabled", event.getEventName()));
        }
    }

    private void handleLoginEvent(Event event, AuthenticationContext context, List<AuthStep> authSteps, boolean isSuccess)
            throws IdentityEventException {

        //TODO: make this also builder pattern
        AuthenticationData authenticationData;
        if (isSuccess) {
            //TODO: buildAuthnDataForAuthentication to util in common
            authenticationData = AnalyticsLoginDataPublisherUtils.buildAuthnDataForAuthentication(event);
        } else {
            authenticationData = AnalyticsLoginDataPublisherUtils.buildAuthnDataForAuthnStep(event);
        }

        if (authenticationData.isPassive()) {
            return;
        }

        try {
            LoginEventPayloadBuilder payloadBuilder = PayloadBuilderFactory.getLoginEventPayloadBuilder(EVENT_SCHEMA_TYPE_WSO2);
            AuthenticatedUser authenticatedUser = EventHookHandlerUtils.getAuthenticatedUserFromEvent(event);
            EventHookHandlerUtils.setLocalUserClaims(authenticatedUser, context);
            EventData eventData = new EventData(authenticationData, authenticatedUser, null, authSteps, context,
                    context.getLoginTenantDomain());
            EventPayload eventPayload = isSuccess ? payloadBuilder.buildAuthenticationSuccessEvent(eventData)
                    : payloadBuilder.buildAuthenticationFailedEvent(eventData);

            //TODO: Pass the event itself to the publishEventPayload method
            publishEventPayload(context, eventPayload, isSuccess);
        } catch (Exception e) {
            throw new IdentityEventException(String.format("Error while handling %s event.", event.getEventName()), e);
        }
    }

    //TODO: Improve the isSuccess variable name
    private void publishEventPayload(AuthenticationContext context, EventPayload eventPayload,
                                     boolean isSuccess) throws Exception {

        String eventUri = EventHookHandlerUtils.getEventUri(isSuccess ? Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT
                : Constants.EventHandlerKey.LOGIN_FAILED_EVENT);
        //TODO: remove extensibility of this event context builder
        EventContext eventContext = EventContext.builder()
                .tenantDomain(context.getLoginTenantDomain())
                .eventUri(eventUri)
                .build();
        SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils.buildSecurityEventToken(eventPayload,
                context, eventUri, eventContext.getTenantDomain());
        EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                .publish(securityEventTokenPayload, eventContext);
    }

    private boolean isLoginEventHandlerEnabled() {

        String enablePropertyKey = Constants.LOGIN_EVENT_HOOK_NAME + "." + Constants.ENABLE;
        return this.configs != null && this.configs.getModuleProperties() != null &&
                Boolean.parseBoolean(configs.getModuleProperties().getProperty(enablePropertyKey));
    }

    private AuthenticationContext getAuthenticationContext(Event event) {

        return (AuthenticationContext) event.getEventProperties().get(IdentityEventConstants.EventProperty.CONTEXT);
    }

    private EventAttribute getLoginEventPublisherConfigForTenant(String tenantDomain, String eventName) {

        if (StringUtils.isEmpty(tenantDomain) || MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            return new EventAttribute();
        }

        try {
            Condition condition = createPublisherConfigFilterCondition();
            Resources publisherConfigResource = EventHookHandlerDataHolder.getInstance().getConfigurationManager()
                    .getTenantResources(tenantDomain, condition);

            return extractEventAttribute(publisherConfigResource, eventName);
        } catch (ConfigurationManagementException | EventConfigurationMgtServerException e) {
            logError(log, "Error while retrieving event publisher configuration for tenant.", e);
        }

        return new EventAttribute();
    }

    private EventAttribute extractEventAttribute(Resources publisherConfigResource, String eventName)
            throws EventConfigurationMgtServerException {

        if (CollectionUtils.isNotEmpty(publisherConfigResource.getResources()) &&
                publisherConfigResource.getResources().get(0) != null &&
                CollectionUtils.isNotEmpty(publisherConfigResource.getResources().get(0).getAttributes())) {

            for (Attribute attribute : publisherConfigResource.getResources().get(0).getAttributes()) {
                if (isMatchingEventAttribute(attribute, eventName)) {
                    return EventConfigurationMgtUtils.buildEventAttributeFromJSONString(attribute.getValue());
                }
            }
        }
        return new EventAttribute();
    }

    private boolean isMatchingEventAttribute(Attribute attribute, String eventName) {

        return (Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT.equals(attribute.getKey()) &&
                eventName.equals(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name())) ||
                (Constants.EventHandlerKey.LOGIN_FAILED_EVENT.equals(attribute.getKey()) &&
                        eventName.equals(IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name()));
    }

    private ComplexCondition createPublisherConfigFilterCondition() {

        List<Condition> conditionList = new ArrayList<>();
        conditionList.add(new PrimitiveCondition(Constants.RESOURCE_TYPE, EQUALS, Constants.WEB_SUB_HUB_CONFIG_RESOURCE_TYPE_NAME));
        conditionList.add(new PrimitiveCondition(Constants.RESOURCE_NAME, EQUALS, Constants.WEB_SUB_HUB_CONFIG_RESOURCE_NAME));
        return new ComplexCondition(ConditionType.ComplexOperator.AND, conditionList);
    }

    private List<AuthStep> convertAuthHistoryToAuthSteps(List<AuthHistory> authHistories) {

        List<AuthStep> authStepsList = new ArrayList<>();
        int authenticationStep = 1;

        if (authHistories != null) {
            for (AuthHistory authHistory : authHistories) {
                AuthStep authStep = new AuthStep();
                authStep.setStep(authenticationStep);
                authStep.setIdp(authHistory.getIdpName());
                authStep.setAuthenticator(authHistory.getAuthenticatorName());
                authStepsList.add(authStep);
                authenticationStep++;
            }
        }
        return authStepsList;
    }

    private AuthStep setFailedStep(AuthenticationContext context) {

        AuthStep failedStep = new AuthStep();
        failedStep.setStep(context.getCurrentStep());
        failedStep.setAuthenticator(context.getCurrentAuthenticator());
        failedStep.setIdp(context.getExternalIdP() != null ?
                context.getExternalIdP().getIdentityProvider().getIdentityProviderName() : null);
        return failedStep;
    }
}
