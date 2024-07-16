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

package org.wso2.identity.webhook.common.event.handler.constant;

/**
 * Constants class.
 */
public class Constants {

    public static final String EVENT_SCHEMA_TYPE_WSO2 = "WSO2";
    public static final String LOGIN_EVENT_HOOK_NAME = "LoginEventHook";
    public static final String ENABLE = "enable";
    public static final String SP_TO_CARBON_CLAIM_MAPPING = "SP_TO_CARBON_CLAIM_MAPPING";

    public static final String WEB_SUB_HUB_CONFIG_RESOURCE_TYPE_NAME = "web-sub-hub-event-publisher";
    public static final String WEB_SUB_HUB_CONFIG_RESOURCE_NAME = "web-sub-hub-event-publisher-configs";
    public static final String RESOURCE_TYPE = "resourceTypeName";
    public static final String RESOURCE_NAME = "resourceName";

    /**
     * Constants for event config names (keys).
     * These names will be equal to the config attribute keys stored in the core config store.
     */
    public static class EventHandlerKey {

        public static final String LOGIN_SUCCESS_EVENT = "logins.loginSuccess";
        public static final String LOGIN_FAILED_EVENT = "logins.loginFailed";

        private EventHandlerKey() {

        }
    }
}
