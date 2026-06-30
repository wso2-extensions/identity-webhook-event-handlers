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

import java.util.List;

/**
 * Represents a purpose entry within a consent record.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ConsentPurpose {

    private final String id;
    private final String name;
    private final String version;
    private final List<ConsentElement> elements;

    private ConsentPurpose(Builder builder) {

        this.id = builder.id;
        this.name = builder.name;
        this.version = builder.version;
        this.elements = builder.elements;
    }

    public String getId() {

        return id;
    }

    public String getName() {

        return name;
    }

    public String getVersion() {

        return version;
    }

    public List<ConsentElement> getElements() {

        return elements;
    }

    public static class Builder {

        private String id;
        private String name;
        private String version;
        private List<ConsentElement> elements;

        public Builder id(String id) {

            this.id = id;
            return this;
        }

        public Builder name(String name) {

            this.name = name;
            return this;
        }

        public Builder version(String version) {

            this.version = version;
            return this;
        }

        public Builder elements(List<ConsentElement> elements) {

            this.elements = elements;
            return this;
        }

        public ConsentPurpose build() {

            return new ConsentPurpose(this);
        }
    }
}
