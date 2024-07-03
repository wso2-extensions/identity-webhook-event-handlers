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

package org.wso2.identity.webhook.wso2.event.handler.model;

import java.util.ArrayList;
import java.util.List;

/**
 * Model Class for Authentication Success Event Payload.
 */
public class WSO2AuthenticationSuccessEventPayload extends WSO2BaseEventPayload {

    private List<String> authenticationMethods = new ArrayList<>();

    public List<String> getAuthenticationMethods() {
        return authenticationMethods;
    }

    public void setAuthenticationMethods(List<String> authenticationMethods) {
        this.authenticationMethods = authenticationMethods;
    }

    public void addAuthenticationMethod(String authenticationMethod) {
        this.authenticationMethods.add(authenticationMethod);
    }
}
