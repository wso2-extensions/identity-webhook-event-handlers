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

import java.util.HashMap;
import java.util.Map;

public class CAEPTokenClaimsChangeEventPayload extends CAEPBaseEventPayload {

    private CAEPTokenClaimsChangeEventPayload(Builder builder) {

        this.initiatingEntity = builder.initiatingEntity;
        this.eventTimeStamp = builder.eventTimeStamp;
        this.reasonAdmin = builder.reasonAdmin;
        this.reasonUser = builder.reasonUser;
        this.claims = builder.claims;
    }

    private Map<String, String> claims;

    public Map<String, String> getClaims() {

        return claims;
    }

    public static class Builder {

        private long eventTimeStamp;
        private String initiatingEntity;
        private Map<String, String> reasonAdmin;
        private Map<String, String> reasonUser;
        private Map<String, String> claims = new HashMap<>();

        public Builder eventTimeStamp(long eventTimeStamp) {

            this.eventTimeStamp = eventTimeStamp;
            return this;
        }

        public Builder initiatingEntity(String initiatingEntity) {

            this.initiatingEntity = initiatingEntity;
            return this;
        }

        public Builder reasonAdmin(Map<String, String> reasonAdmin) {

            this.reasonAdmin = reasonAdmin;
            return this;
        }

        public Builder reasonUser(Map<String, String> reasonUser) {

            this.reasonUser = reasonUser;
            return this;
        }

        public Builder claims(Map<String, String> claims) {

            this.claims = claims;
            return this;
        }

        public CAEPTokenClaimsChangeEventPayload build() {

            return new CAEPTokenClaimsChangeEventPayload(this);
        }
    }
}
