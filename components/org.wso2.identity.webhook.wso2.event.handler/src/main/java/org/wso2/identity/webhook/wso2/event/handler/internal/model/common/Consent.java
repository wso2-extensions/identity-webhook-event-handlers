/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.wso2.event.handler.internal.model.common;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Represents the consent record embedded in consent event payloads.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Consent {

    private final String id;
    private final String subjectId;
    private final String state;
    private final String serviceId;
    private final ConsentPurpose purpose;

    private Consent(Builder builder) {

        this.id = builder.id;
        this.subjectId = builder.subjectId;
        this.state = builder.state;
        this.serviceId = builder.serviceId;
        this.purpose = builder.purpose;
    }

    public String getId() {

        return id;
    }

    public String getSubjectId() {

        return subjectId;
    }

    public String getState() {

        return state;
    }

    public String getServiceId() {

        return serviceId;
    }

    public ConsentPurpose getPurpose() {

        return purpose;
    }

    public static class Builder {

        private String id;
        private String subjectId;
        private String state;
        private String serviceId;
        private ConsentPurpose purpose;

        public Builder id(String id) {

            this.id = id;
            return this;
        }

        public Builder subjectId(String subjectId) {

            this.subjectId = subjectId;
            return this;
        }

        public Builder state(String state) {

            this.state = state;
            return this;
        }

        public Builder serviceId(String serviceId) {

            this.serviceId = serviceId;
            return this;
        }

        public Builder purpose(ConsentPurpose purpose) {

            this.purpose = purpose;
            return this;
        }

        public Consent build() {

            return new Consent(this);
        }
    }
}
