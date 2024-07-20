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

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.model.EventAttribute;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.common.event.handler.model.ResourceConfig;
import org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
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
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;

import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType.PrimitiveOperator.EQUALS;
import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_SCHEMA_TYPE_WSO2;
import static org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils.*;

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

        boolean canHandle = isSupportedEvent(eventName);
        log.debug("canHandle() returning " + canHandle + " for the event: " + eventName);
        return canHandle;
    }

    private boolean isSupportedEvent(String eventName) {

        return IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(eventName) ||
                IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(eventName) ||
                IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name().equals(eventName);
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = buildEventDataProvider(event);

        if (eventData.getAuthenticationContext().isPassiveAuthenticate()) {
            return;
        }

        //TODO: Add the implementation to read the Event Schema Type from the Tenant Configuration
        LoginEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                .getLoginEventPayloadBuilder(EVENT_SCHEMA_TYPE_WSO2);
        EventAttribute loginEventPublisherConfig = getLoginEventPublisherConfigForTenant(
                eventData.getAuthenticationContext().getLoginTenantDomain(), event.getEventName());
        EventPayload eventPayload;
        String eventUri;

        if (IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name().equals(event.getEventName()) &&
                loginEventPublisherConfig.isPublishEnabled()) {
            eventPayload = payloadBuilder.buildAuthenticationSuccessEvent(eventData);
            eventUri = EventHookHandlerUtils.getEventUri(Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT);
            String tenantDomain = eventData.getAuthenticationContext().getLoginTenantDomain();
            SecurityEventTokenPayload securityEventTokenPayload = buildSecurityEventToken(eventPayload, eventUri);
            EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
        } else if (IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name().equals(event.getEventName()) &&
                loginEventPublisherConfig.isPublishEnabled()) {
            eventPayload = payloadBuilder.buildAuthenticationFailedEvent(eventData);
            eventUri = EventHookHandlerUtils.getEventUri(Constants.EventHandlerKey.LOGIN_FAILED_EVENT);
            String tenantDomain = eventData.getAuthenticationContext().getLoginTenantDomain();
            SecurityEventTokenPayload securityEventTokenPayload = buildSecurityEventToken(eventPayload, eventUri);
            EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
        }
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
        } catch (ConfigurationManagementException | IdentityEventException e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }

        return new EventAttribute();
    }

    private EventAttribute extractEventAttribute(Resources publisherConfigResource, String eventName) throws IdentityEventException {

        if (CollectionUtils.isNotEmpty(publisherConfigResource.getResources()) &&
                publisherConfigResource.getResources().get(0) != null &&
                CollectionUtils.isNotEmpty(publisherConfigResource.getResources().get(0).getAttributes())) {

            for (Attribute attribute : publisherConfigResource.getResources().get(0).getAttributes()) {
                if (isMatchingEventAttribute(attribute, eventName)) {
                    return buildEventAttributeFromJSONString(attribute.getValue());
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
        conditionList.add(new PrimitiveCondition(Constants.RESOURCE_TYPE, EQUALS, Constants.EVENT_PUBLISHER_CONFIG_RESOURCE_TYPE_NAME));
        conditionList.add(new PrimitiveCondition(Constants.RESOURCE_NAME, EQUALS, Constants.EVENT_PUBLISHER_CONFIG_RESOURCE_NAME));
        return new ComplexCondition(ConditionType.ComplexOperator.AND, conditionList);
    }

    /**
     * This method constructs the EventAttribute object from the json string.
     *
     * @param jsonString JSON string.
     * @return EventAttribute object.
     */
    private EventAttribute buildEventAttributeFromJSONString(String jsonString) throws IdentityEventException {

        JSONObject eventJSON = getJSONObject(jsonString);
        EventAttribute eventAttribute = new EventAttribute();
        try {
            if (eventJSON.get(Constants.EVENT_PUBLISHER_CONFIG_ATTRIBUTE_PUBLISH_ENABLED_KEY) instanceof Boolean) {
                eventAttribute.setPublishEnabled(
                        (Boolean) eventJSON.get(Constants.EVENT_PUBLISHER_CONFIG_ATTRIBUTE_PUBLISH_ENABLED_KEY));
            } else {
                eventAttribute.setPublishEnabled(Boolean.parseBoolean(
                        (String) eventJSON.get(Constants.EVENT_PUBLISHER_CONFIG_ATTRIBUTE_PUBLISH_ENABLED_KEY)));
            }
            JSONObject propertiesJSON =
                    (JSONObject) eventJSON.get(Constants.EVENT_PUBLISHER_CONFIG_ATTRIBUTE_PROPERTIES_KEY);
            eventAttribute.setProperties(new ResourceConfig(propertiesJSON));

            return eventAttribute;
        } catch (ClassCastException e) {
            throw new IdentityEventException("Error while casting event attribute from JSON string", e);
        }
    }

    /**
     * This method converts the parsed JSON String into a JSONObject.
     *
     * @param jsonString JSON string.
     * @return JSON object.
     * @throws IdentityEventServerException If an error occurs while constructing the object.
     */
    private JSONObject getJSONObject(String jsonString) throws IdentityEventServerException {

        JSONParser jsonParser = new JSONParser();
        try {
            return (JSONObject) jsonParser.parse(jsonString);
        } catch (ParseException | ClassCastException e) {
            throw new IdentityEventServerException("Error while parsing JSON string", e);
        }
    }
}
