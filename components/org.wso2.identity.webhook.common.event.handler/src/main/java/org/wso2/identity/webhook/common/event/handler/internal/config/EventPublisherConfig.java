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

package org.wso2.identity.webhook.common.event.handler.internal.config;

import org.json.simple.JSONObject;

/**
 * Model class representing the event attributes.
 */
public class EventPublisherConfig {

    private boolean publishEnabled;
    private ResourceConfig properties;

    /**
     * Constructs event attribute with default configs.
     */
    public EventPublisherConfig() {

        this.publishEnabled = false;
        this.properties = new ResourceConfig(new JSONObject());
    }

    /**
     * Construct event attribute.
     *
     * @param publishEnabled Is publishing enabled.
     * @param properties     Event properties.
     */
    public EventPublisherConfig(boolean publishEnabled, ResourceConfig properties) {

        this.publishEnabled = publishEnabled;
        this.properties = properties;
    }

    public boolean isPublishEnabled() {

        return publishEnabled;
    }

    public void setPublishEnabled(boolean publishEnabled) {

        this.publishEnabled = publishEnabled;
    }

    public ResourceConfig getProperties() {

        return properties;
    }

    public void setProperties(ResourceConfig properties) {

        this.properties = properties;
    }
}
