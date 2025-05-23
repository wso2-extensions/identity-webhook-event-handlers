/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.caep.event.handler.api.builder;

import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPCredentialChangeEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.Map;

import static org.wso2.identity.webhook.caep.event.handler.internal.utils.CAEPEventUtils.extractEventTimeStamp;
import static org.wso2.identity.webhook.caep.event.handler.internal.utils.CAEPEventUtils.extractInitiatingEntity;

public class CAEPCredentialEventPayloadBuilder implements CredentialEventPayloadBuilder {

    @Override
    public EventPayload buildUpdatePasswordByUser(EventData eventData) {

        long eventTimeStamp = extractEventTimeStamp(eventData.getEventParams());

        Map<String, String> reasonAdmin = new java.util.HashMap<>();
        reasonAdmin.put("en", "Password Update by User");

        Map<String, String> reasonUser = new java.util.HashMap<>();
        reasonUser.put("en", "Password Changed by User");

        return new CAEPCredentialChangeEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity("user")
                .reasonAdmin(reasonAdmin)
                .reasonUser(reasonUser)
                .credentialType("password")
                .changeType(CAEPCredentialChangeEventPayload.ChangeType.UPDATE)
                .friendlyName("Password")
                .build();
    }

    @Override
    public EventPayload buildUpdatePasswordByAdmin(EventData eventData) {

        long eventTimeStamp = extractEventTimeStamp(eventData.getEventParams());

        Map<String, String> reasonAdmin = new java.util.HashMap<>();
        reasonAdmin.put("en", "Password Update by Admin");

        Map<String, String> reasonUser = new java.util.HashMap<>();
        reasonUser.put("en", "Password Changed by Admin");

        return new CAEPCredentialChangeEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity("admin")
                .reasonAdmin(reasonAdmin)
                .reasonUser(reasonUser)
                .credentialType("password")
                .changeType(CAEPCredentialChangeEventPayload.ChangeType.UPDATE)
                .friendlyName("Password")
                .build();
    }

    @Override
    public EventPayload buildAddNewPassword(EventData eventData) {

        long eventTimeStamp = extractEventTimeStamp(eventData.getEventParams());

        String initiatingEntity = null;

        Flow flow = eventData.getFlow();
        if (flow != null) {
            initiatingEntity = extractInitiatingEntity(flow.getInitiatingPersona());
        }

        Map<String, String> reasonAdmin = new java.util.HashMap<>();
        reasonAdmin.put("en", "Create new password");

        Map<String, String> reasonUser = new java.util.HashMap<>();
        reasonUser.put("en", "Created a new password");

        return new CAEPCredentialChangeEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity(initiatingEntity)
                .reasonAdmin(reasonAdmin)
                .reasonUser(reasonUser)
                .credentialType("password")
                .changeType(CAEPCredentialChangeEventPayload.ChangeType.CREATE)
                .friendlyName("Password")
                .build();
    }

    @Override
    public EventSchema getEventSchemaType() {

        return EventSchema.CAEP;
    }
}
