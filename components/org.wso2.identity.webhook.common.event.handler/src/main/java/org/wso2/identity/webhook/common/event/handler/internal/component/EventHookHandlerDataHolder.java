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

package org.wso2.identity.webhook.common.event.handler.internal.component;

import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * A data holder class to keep the data of the event handler component.
 */
public class EventHookHandlerDataHolder {

    private static final EventHookHandlerDataHolder instance = new EventHookHandlerDataHolder();
    private ConfigurationManager configurationManager;
    private EventPublisherService eventPublisherService;
    private List<LoginEventPayloadBuilder> loginEventPayloadBuilders = new ArrayList<>();

    private EventHookHandlerDataHolder() {
    }

    public static EventHookHandlerDataHolder getInstance() {

        return instance;
    }

    /**
     * Get the list of login event payload builder implementations available.
     *
     * @return List of login event payload builder implementations.
     */
    public List<LoginEventPayloadBuilder> getLoginEventPayloadBuilders() {

        return loginEventPayloadBuilders;
    }

    /**
     * Set a list of login event payload builders.
     *
     * @param loginEventPayloadBuilders List of login event payload builders.
     */
    public void setLoginEventPayloadBuilders(List<LoginEventPayloadBuilder> loginEventPayloadBuilders) {

        this.loginEventPayloadBuilders = loginEventPayloadBuilders;
    }

    /**
     * Add login event payload builder implementation.
     *
     * @param loginEventPayloadBuilder Login event payload builder implementation.
     */
    public void addLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        loginEventPayloadBuilders.add(loginEventPayloadBuilder);
    }

    /**
     * Remove login event payload builder implementation.
     *
     * @param loginEventPayloadBuilder Login event payload builder implementation.
     */
    public void removeLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        loginEventPayloadBuilders.remove(loginEventPayloadBuilder);
    }

    /**
     * Get the configuration manager.
     *
     * @return Configuration manager.
     */
    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }

    /**
     * Set the configuration manager.
     *
     * @param configurationManager Configuration manager.
     */
    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }

    /**
     * Get the event publisher service.
     *
     * @return Event publisher service.
     */
    public EventPublisherService getEventPublisherService() {

        return eventPublisherService;
    }

    /**
     * Set the event publisher service.
     *
     * @param eventPublisherService Event publisher service.
     */
    public void setEventPublisherService(EventPublisherService eventPublisherService) {

        this.eventPublisherService = eventPublisherService;
    }
}
