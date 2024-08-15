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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.configuration.mgt.core.search.ComplexCondition;
import org.wso2.carbon.identity.configuration.mgt.core.search.Condition;
import org.wso2.carbon.identity.configuration.mgt.core.search.PrimitiveCondition;
import org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.common.event.handler.model.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType.PrimitiveOperator.EQUALS;
import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_SCHEMA_TYPE_WSO2;

/**
 * Login Event Hook Handler.
 */
public class LoginEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(LoginEventHookHandler.class);
    private final EventHookHandlerUtils eventHookHandlerUtils;
    private final EventConfigManager eventConfigManager;

    public LoginEventHookHandler(EventHookHandlerUtils eventHookHandlerUtils,  EventConfigManager eventConfigManager) {
        this.eventHookHandlerUtils = eventHookHandlerUtils;
        this.eventConfigManager = eventConfigManager;
    }

    @Override
    public String getName() {

        return Constants.LOGIN_EVENT_HOOK_NAME;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        IdentityEventMessageContext identityContext = (IdentityEventMessageContext) messageContext;
        String eventName = identityContext.getEvent().getEventName();

        boolean canHandle = isSupportedEvent(eventName);
        if (canHandle) {
            log.debug(eventName + " event can be handled.");
        } else {
            log.debug(eventName + " event cannot be handled.");
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

        EventData eventData = eventHookHandlerUtils.buildEventDataProvider(event);

        if (eventData.getAuthenticationContext().isPassiveAuthenticate()) {
            return;
        }

        //TODO: Add the implementation to read the Event Schema Type from the Tenant Configuration
        LoginEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                .getLoginEventPayloadBuilder(EVENT_SCHEMA_TYPE_WSO2);
        EventPublisherConfig loginEventPublisherConfig = null;
        try {
            loginEventPublisherConfig = getLoginEventPublisherConfigForTenant(
                    eventData.getAuthenticationContext().getLoginTenantDomain(), event.getEventName());

            EventPayload eventPayload;
            String eventUri;

            if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(event.getEventName()) &&
                    loginEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildAuthenticationSuccessEvent(eventData);
                eventUri = eventConfigManager.getEventUri(Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT);
                String tenantDomain = eventData.getAuthenticationContext().getLoginTenantDomain();
                SecurityEventTokenPayload securityEventTokenPayload = eventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                eventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            } else if (IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name()
                    .equals(event.getEventName()) &&
                    loginEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildAuthenticationFailedEvent(eventData);
                eventUri = eventConfigManager.getEventUri(Constants.EventHandlerKey.LOGIN_FAILED_EVENT);
                String tenantDomain = eventData.getAuthenticationContext().getLoginTenantDomain();
                SecurityEventTokenPayload securityEventTokenPayload = eventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                eventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            }
        } catch (IdentityEventException e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }
    }

    private EventPublisherConfig getLoginEventPublisherConfigForTenant(String tenantDomain, String eventName)
            throws IdentityEventException {

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

    private ComplexCondition createPublisherConfigFilterCondition() {

        List<Condition> conditionList = new ArrayList<>();
        conditionList.add(new PrimitiveCondition(Constants.RESOURCE_TYPE, EQUALS,
                Constants.EVENT_PUBLISHER_CONFIG_RESOURCE_TYPE_NAME));
        conditionList.add(new PrimitiveCondition(Constants.RESOURCE_NAME, EQUALS,
                Constants.EVENT_PUBLISHER_CONFIG_RESOURCE_NAME));
        return new ComplexCondition(ConditionType.ComplexOperator.AND, conditionList);
    }
}
