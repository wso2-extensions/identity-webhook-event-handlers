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
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.model.ResourceConfig;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This class manages event-related configurations.
 */
public class EventConfigManager {

    private volatile ResourceConfig eventSchema = null;
    private final Object lock = new Object();
    private static volatile EventConfigManager instance;

    private EventConfigManager() {}

    public static EventConfigManager getInstance() {

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

        try {
            ResourceConfig eventConfigObject = getEventConfig(eventName);
            if (eventConfigObject.getConfigs() != null &&
                    eventConfigObject.getConfigs().containsKey(Constants.EVENT_CONFIG_SCHEMA_NAME_KEY)) {
                return (String) eventConfigObject.getConfigs().get(Constants.EVENT_CONFIG_SCHEMA_NAME_KEY);
            } else {
                throw new IdentityEventServerException("Event schema not found in the resource event config " +
                        "for the eventName: " + eventName);
            }
        } catch (ClassCastException e) {
            throw new IdentityEventServerException("Error while casting event config at server side", e);
        }
    }

    /**
     * Retrieve the event config.
     *
     * @param eventName Event name.
     * @return Resource config object.
     * @throws IdentityEventServerException If an error occurs.
     */
    private ResourceConfig getEventConfig(String eventName) throws IdentityEventServerException {

        JSONObject eventsConfigObject = (JSONObject) getEventsSchemaResourceFile().getConfigs()
                .get(Constants.EVENT_SCHEMA_EVENTS_KEY);
        if (eventsConfigObject != null && !eventsConfigObject.isEmpty() &&
                eventsConfigObject.containsKey(eventName)) {
            return new ResourceConfig((JSONObject) eventsConfigObject.get(eventName));
        } else {
            throw new IdentityEventServerException("Event schema not found in the resource event config " +
                    "for the eventName: " + eventName);
        }
    }

    /**
     * This method reads the event schema resource file and returns the config object.
     *
     * @return Config object with content in the resource file.
     * @throws IdentityEventServerException If an error occurs while reading the resource file.
     */
    private ResourceConfig getEventsSchemaResourceFile() throws IdentityEventServerException {

        if (eventSchema == null) {
            synchronized (lock) {
                if (eventSchema == null) {
                    String resourceFilePath = new File(".").getAbsolutePath() + File.separator +
                            Constants.EVENT_PUBLISHER_EVENT_SCHEMA_RESOURCE_FILE_PATH;
                    JSONParser jsonParser = new JSONParser();
                    try {
                        JSONObject eventConfigJSON = (JSONObject) jsonParser.parse(new InputStreamReader(
                                Files.newInputStream(Paths.get(resourceFilePath)), StandardCharsets.UTF_8)
                        );
                        eventSchema = new ResourceConfig(eventConfigJSON);
                    } catch (IOException | ParseException | ClassCastException e) {
                        throw new IdentityEventServerException("Error while reading the event schema file", e);
                    }
                }
            }
        }

        return eventSchema;
    }
}
