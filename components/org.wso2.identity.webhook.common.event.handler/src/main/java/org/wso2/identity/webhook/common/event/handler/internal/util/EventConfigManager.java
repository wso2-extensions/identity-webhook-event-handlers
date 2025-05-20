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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.configuration.mgt.core.search.ComplexCondition;
import org.wso2.carbon.identity.configuration.mgt.core.search.Condition;
import org.wso2.carbon.identity.configuration.mgt.core.search.PrimitiveCondition;
import org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.config.ResourceConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.configuration.mgt.core.search.constant.ConditionType.PrimitiveOperator.EQUALS;

/**
 * This class manages event-related configurations.
 */
public class EventConfigManager {

    private static volatile EventConfigManager instance;
    private final ResourceConfig eventSchema;

    EventConfigManager() throws IdentityEventServerException {

        String resourceFilePath = new File(".").getAbsolutePath() + File.separator +
                Constants.EVENT_PUBLISHER_EVENT_SCHEMA_RESOURCE_FILE_PATH;
        JSONParser jsonParser = new JSONParser();
        try {
            JSONObject eventConfigJSON = (JSONObject) jsonParser.parse(new InputStreamReader(
                    Files.newInputStream(Paths.get(resourceFilePath)), StandardCharsets.UTF_8)
            );
            eventSchema = new ResourceConfig(eventConfigJSON);
        } catch (IOException | ParseException | ClassCastException e) {
            throw new IdentityEventServerException("Error while reading the event schema file: " +
                    resourceFilePath, e);
        }
    }

    public static EventConfigManager getInstance() throws IdentityEventServerException {

        if (instance == null) {
            synchronized (EventConfigManager.class) {
                if (instance == null) {
                    instance = new EventConfigManager();
                }
            }
        }
        return instance;
    }

    /**
     * Retrieve the event URI.
     *
     * @param eventName Event name.
     * @return Event URI string.
     * @throws IdentityEventServerException If an error occurs.
     */
    public String getEventUri(String eventName) throws IdentityEventServerException {

        ResourceConfig eventConfigObject = getEventConfig(eventName);
        if (eventConfigObject != null && eventConfigObject.getConfigs() != null &&
                eventConfigObject.getConfigs().containsKey(Constants.EVENT_CONFIG_SCHEMA_NAME_KEY)) {
            return (String) eventConfigObject.getConfigs().get(Constants.EVENT_CONFIG_SCHEMA_NAME_KEY);
        } else {
            throw new IdentityEventServerException("Event schema for event name: " + eventName + " not found in " +
                    Constants.EVENT_PUBLISHER_EVENT_SCHEMA_RESOURCE_FILE_PATH + " file");
        }
    }

    /**
     * Retrieve the event config.
     *
     * @param eventName Event name.
     * @return Resource config object.
     */
    private ResourceConfig getEventConfig(String eventName) {

        JSONObject eventsConfigObject = (JSONObject) eventSchema.getConfigs()
                .get(Constants.EVENT_SCHEMA_EVENTS_KEY);
        if (eventsConfigObject != null && !eventsConfigObject.isEmpty() &&
                eventsConfigObject.containsKey(eventName)) {
            return new ResourceConfig((JSONObject) eventsConfigObject.get(eventName));
        }
        return null;
    }

    /**
     * Extract the event publisher configuration.
     *
     * @param publisherConfigResource Publisher config resource.
     * @param eventName               Event name.
     * @return EventPublisherConfig object.
     * @throws IdentityEventException If an error occurs.
     */
    public EventPublisherConfig extractEventPublisherConfig(Resources publisherConfigResource, String eventName)
            throws IdentityEventException {

        if (CollectionUtils.isNotEmpty(publisherConfigResource.getResources()) &&
                publisherConfigResource.getResources().get(0) != null &&
                CollectionUtils.isNotEmpty(publisherConfigResource.getResources().get(0).getAttributes())) {

            for (Attribute attribute : publisherConfigResource.getResources().get(0).getAttributes()) {
                if (isMatchingEventPublisherConfig(attribute, eventName)) {
                    return buildEventPublisherConfigFromJSONString(attribute.getValue());
                }
            }
        }
        return new EventPublisherConfig();
    }

    /**
     * Retrieves the EventPublisherConfig for a given tenant domain and event name.
     * This method fetches the event publisher configuration from the configuration management system
     * for the specified tenant. If the configuration cannot be retrieved
     * or an error occurs during the process, an IdentityEventException is thrown.
     *
     * @param tenantDomain the domain name of the tenant for which the configuration is being retrieved.
     * @param eventName    the name of the event for which the publisher configuration is required.
     * @return the EventPublisherConfig corresponding to the specified tenant and event.
     * @throws IdentityEventException if the tenant domain is invalid or an error occurs while retrieving the
     *                                configuration.
     */
    public EventPublisherConfig getEventPublisherConfigForTenant(String tenantDomain, String eventName)
            throws IdentityEventException {

        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IdentityEventException("Invalid tenant domain: " + tenantDomain);
        }

        try {
            Condition condition = createPublisherConfigFilterCondition();
            Resources publisherConfigResource = EventHookHandlerDataHolder.getInstance().getConfigurationManager()
                    .getTenantResources(tenantDomain, condition);
            return extractEventPublisherConfig(publisherConfigResource, eventName);
        } catch (ConfigurationManagementException e) {
            throw new IdentityEventException("Error while retrieving event publisher configuration for tenant.", e);
        }
    }

    private boolean isMatchingEventPublisherConfig(Attribute attribute, String eventName) {

        if ((Constants.EventHandlerKey.WSO2.LOGIN_SUCCESS_EVENT.equals(attribute.getKey()))
                && (eventName.equals(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name()))) {
            return true;
        }
        if ((Constants.EventHandlerKey.WSO2.LOGIN_FAILED_EVENT.equals(attribute.getKey()))) {
            return ((eventName.equals(IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name()))) ||
                    (eventName.equals(IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name()));
        }

        if ((Constants.EventHandlerKey.WSO2.POST_UPDATE_USER_LIST_OF_ROLE_EVENT.equals(attribute.getKey()) &&
                eventName.equals(IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE))) {
            return true;
        }

        if (Constants.EventHandlerKey.CAEP.SESSION_REVOKED_EVENT.equals(attribute.getKey())) {
            return eventName.equals(IdentityEventConstants.EventName.USER_SESSION_TERMINATE.name());
        }
        if (Constants.EventHandlerKey.CAEP.SESSION_ESTABLISHED_EVENT.equals(attribute.getKey())) {
            return (eventName.equals(IdentityEventConstants.EventName.SESSION_CREATE.name()));
        }
        if (Constants.EventHandlerKey.CAEP.SESSION_PRESENTED_EVENT.equals(attribute.getKey())) {
            return (eventName.equals(IdentityEventConstants.EventName.SESSION_UPDATE.name())
                    || eventName.equals(IdentityEventConstants.EventName.SESSION_EXTEND.name()));
        }
        if (Constants.EventHandlerKey.CAEP.VERIFICATION_EVENT.equals(attribute.getKey())) {
            return (eventName.equals(IdentityEventConstants.EventName.VERIFICATION.name()));
        }
        return false;
    }

    private EventPublisherConfig buildEventPublisherConfigFromJSONString(String jsonString)
            throws IdentityEventException {

        JSONObject eventJSON = getJSONObject(jsonString);
        EventPublisherConfig eventPublisherConfig = new EventPublisherConfig();
        try {
            if (eventJSON.get(Constants.EVENT_PUBLISHER_CONFIG_ATTRIBUTE_PUBLISH_ENABLED_KEY) instanceof Boolean) {
                eventPublisherConfig.setPublishEnabled(
                        (Boolean) eventJSON.get(Constants.EVENT_PUBLISHER_CONFIG_ATTRIBUTE_PUBLISH_ENABLED_KEY));
            } else {
                eventPublisherConfig.setPublishEnabled(Boolean.parseBoolean(
                        (String) eventJSON.get(Constants.EVENT_PUBLISHER_CONFIG_ATTRIBUTE_PUBLISH_ENABLED_KEY)));
            }
            JSONObject propertiesJSON =
                    (JSONObject) eventJSON.get(Constants.EVENT_PUBLISHER_CONFIG_ATTRIBUTE_PROPERTIES_KEY);
            eventPublisherConfig.setProperties(new ResourceConfig(propertiesJSON));

            return eventPublisherConfig;
        } catch (ClassCastException e) {
            throw new IdentityEventException("Error while casting event attribute from JSON string", e);
        }
    }

    private JSONObject getJSONObject(String jsonString) throws IdentityEventServerException {

        JSONParser jsonParser = new JSONParser();
        try {
            return (JSONObject) jsonParser.parse(jsonString);
        } catch (ParseException | ClassCastException e) {
            throw new IdentityEventServerException("Error while parsing JSON string", e);
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
