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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public class CAEPCredentialChangeEventPayload extends CAEPBaseEventPayload {

    private CAEPCredentialChangeEventPayload(Builder builder) {

        this.initiatingEntity = builder.initiatingEntity;
        this.eventTimeStamp = builder.eventTimeStamp;
        this.reasonAdmin = builder.reasonAdmin;
        this.reasonUser = builder.reasonUser;
        this.credentialType = builder.credentialType;
        this.changeType = builder.changeType;
        this.friendlyName = builder.friendlyName;
        this.x509Issuer = builder.x509Issuer;
        this.x509Serial = builder.x509Serial;
        this.fidoAaguid = builder.fidoAaguid;
    }

    @JsonProperty("credential_type")
    private final String credentialType;

    @JsonProperty("change_type")
    private final String changeType;

    @JsonProperty("friendly_name")
    private final String friendlyName;

    @JsonProperty("x509_issuer")
    private final String x509Issuer;

    @JsonProperty("x509_serial")
    private final String x509Serial;

    @JsonProperty("fido_aaguid")
    private final String fidoAaguid;

    public String getCredentialType() {

        return credentialType;
    }

    public String getChangeType() {

        return changeType;
    }

    public String getFriendlyName() {

        return friendlyName;
    }

    public String getX509Issuer() {

        return x509Issuer;
    }

    public String getX509Serial() {

        return x509Serial;
    }

    public String getFidoAaguid() {

        return fidoAaguid;
    }

    public static class Builder {

        private long eventTimeStamp;
        private String initiatingEntity;
        private Map<String, String> reasonAdmin;
        private Map<String, String> reasonUser;
        private String credentialType;
        private String changeType;
        private String friendlyName;
        private String x509Issuer;
        private String x509Serial;
        private String fidoAaguid;

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

        public Builder credentialType(String credentialType) {

            this.credentialType = credentialType;
            return this;
        }

        public Builder changeType(String changeType) {

            this.changeType = changeType;
            return this;
        }

        public Builder friendlyName(String friendlyName) {

            this.friendlyName = friendlyName;
            return this;
        }

        public Builder x509Issuer(String x509Issuer) {

            this.x509Issuer = x509Issuer;
            return this;
        }

        public Builder x509Serial(String x509Serial) {

            this.x509Serial = x509Serial;
            return this;
        }

        public Builder fidoAaguid(String fidoAaguid) {

            this.fidoAaguid = fidoAaguid;
            return this;
        }

        public CAEPCredentialChangeEventPayload build() {

            return new CAEPCredentialChangeEventPayload(this);
        }
    }
}
