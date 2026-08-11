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

/**
 * Represents the organization an organization management event acted on, with its management API ref URL.
 */
public class OrganizationRef {

    private final String id;
    private final String name;
    private final String description;
    private final String status;
    private final String type;
    private final String orgHandle;
    private final String parentId;
    private final String ref;

    private OrganizationRef(Builder builder) {

        this.id = builder.id;
        this.name = builder.name;
        this.description = builder.description;
        this.status = builder.status;
        this.type = builder.type;
        this.orgHandle = builder.orgHandle;
        this.parentId = builder.parentId;
        this.ref = builder.ref;
    }

    public String getId() {

        return id;
    }

    public String getName() {

        return name;
    }

    public String getDescription() {

        return description;
    }

    public String getStatus() {

        return status;
    }

    public String getType() {

        return type;
    }

    public String getOrgHandle() {

        return orgHandle;
    }

    public String getParentId() {

        return parentId;
    }

    public String getRef() {

        return ref;
    }

    /**
     * Builder for OrganizationRef.
     */
    public static class Builder {

        private String id;
        private String name;
        private String description;
        private String status;
        private String type;
        private String orgHandle;
        private String parentId;
        private String ref;

        public Builder id(String id) {

            this.id = id;
            return this;
        }

        public Builder name(String name) {

            this.name = name;
            return this;
        }

        public Builder description(String description) {

            this.description = description;
            return this;
        }

        public Builder status(String status) {

            this.status = status;
            return this;
        }

        public Builder type(String type) {

            this.type = type;
            return this;
        }

        public Builder orgHandle(String orgHandle) {

            this.orgHandle = orgHandle;
            return this;
        }

        public Builder parentId(String parentId) {

            this.parentId = parentId;
            return this;
        }

        public Builder ref(String ref) {

            this.ref = ref;
            return this;
        }

        public OrganizationRef build() {

            return new OrganizationRef(this);
        }
    }
}
