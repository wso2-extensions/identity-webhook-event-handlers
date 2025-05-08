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

package org.wso2.identity.webhook.caep.event.handler.internal.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.wso2.identity.event.common.publisher.model.EventPayload;

import java.util.Map;

/**
 * Base class for CAEP event payloads.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public abstract class CAEPBaseEventPayload extends EventPayload {

    @JsonProperty("event_timestamp")
    protected long eventTimeStamp;

    @JsonProperty("initiating_entity")
    protected String initiatingEntity;

    @JsonProperty("reason_admin")
    protected Map<String, String> reasonAdmin;

    @JsonProperty("reason_user")
    protected Map<String, String> reasonUser;

    public long getEventTimeStamp() {

        return eventTimeStamp;
    }

    public String getInitiatingEntity() {

        return initiatingEntity;
    }

    public Map<String, String> getReasonAdmin() {

        return reasonAdmin;
    }

    public Map<String, String> getReasonUser() {

        return reasonUser;
    }
}
