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

package org.wso2.identity.webhook.common.event.handler.internal.constant;

/**
 * Constants class.
 */
public class Constants {

    public static final String LOGIN_EVENT_HOOK_NAME = "LoginEventHook";
    public static final String EVENT_PROFILE_VERSION = "v1";
    public static final String LOGIN_EVENT_HOOK_ENABLED = "LoginEventHook.enable";

    public static final String USER_OPERATION_EVENT_HOOK_NAME = "UserOperationEventHook";
    public static final String USER_OPERATION_EVENT_HOOK_ENABLED = "UserOperationEventHook.enable";

    public static final String REGISTRATION_EVENT_HOOK_NAME = "RegistrationEventHook";
    public static final String REGISTRATION_EVENT_HOOK_ENABLED = "RegistrationEventHook.enable";

    public static final String SP_TO_CARBON_CLAIM_MAPPING = "SP_TO_CARBON_CLAIM_MAPPING";

    public static final String SESSION_EVENT_HOOK_NAME = "SessionEventHook";
    public static final String SESSION_EVENT_HOOK_ENABLED = "SessionEventHook.enable";

    public static final String CREDENTIAL_EVENT_HOOK_NAME = "CredentialEventHook";
    public static final String CREDENTIAL_EVENT_HOOK_ENABLED = "CredentialEventHook.enable";

    public static final String VERIFICATION_EVENT_HOOK_NAME = "VerificationEventHook";
    public static final String VERIFICATION_EVENT_HOOK_ENABLED = "VerificationEventHook.enable";

    /**
     * Constants for event data keys.
     * These names will be equal to the keys in the event data map.
     */
    public static class EventDataProperties {

        public static final String CONTEXT = "context";
        public static final String USER = "user";
        public static final String SESSION_DATA = "sessionData";
        public static final String SESSIONS = "sessions";
        public static final String SESSION_ID = "sessionId";
        public static final String SESSION_CONTEXT = "sessionContext";
        public static final String EVENT_TIMESTAMP = "eventTimestamp";
        public static final String STREAM_ID = "streamId";
        public static final String PARAMS = "params";
        public static final String AUTHENTICATION_STATUS = "authenticationStatus";
        public static final String REQUEST = "request";
        public static final String STATE = "state";
        public static final String FLOW = "flow";
    }

    public static final String PRE_DELETE_USER_ID = "PRE_DELETE_USER_ID";

}
