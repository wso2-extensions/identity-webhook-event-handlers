/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
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

package org.wso2.identity.webhook.wso2.event.handler.builder;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.model.WSO2AuthenticationFailedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.model.WSO2AuthenticationSuccessEventPayload;
import org.wso2.identity.event.common.publisher.model.EventPayload;

import java.util.ArrayList;

import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_SCHEMA_TYPE_WSO2;

/**
 * WSO2 Login Event Payload Builder.
 */
public class WSO2LoginEventPayloadBuilder implements LoginEventPayloadBuilder {

    @Override
    public EventPayload buildAuthenticationSuccessEvent(EventData eventData) throws IdentityEventException {

        //TODO: Implement the logic to build the authentication success event payload.
        return new WSO2AuthenticationSuccessEventPayload.Builder()
                .user(null)
                .tenant(null)
                .userResidentOrganization(null)
                .userStore(null)
                .application(null)
                .authenticationMethods(new ArrayList<>())
                .build();
    }

    @Override
    public EventPayload buildAuthenticationFailedEvent(EventData eventData) throws IdentityEventException {

        //TODO: Implement the logic to build the authentication failed event payload.
        return new WSO2AuthenticationFailedEventPayload.Builder()
                .user(null)
                .tenant(null)
                .userResidentOrganization(null)
                .userStore(null)
                .application(null)
                .reason(null)
                .userLoginIdentifier(null)
                .build();
    }

    @Override
    public String getEventSchemaType() {
        return EVENT_SCHEMA_TYPE_WSO2;
    }
}
