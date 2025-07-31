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

package org.wso2.identity.webhook.wso2.event.handler.internal.model.common;

/**
 * Organization class.
 */
public class Organization {

    private final String id;
    private final String name;
    private final String orgHandle;
    private final int depth;

    public Organization(String id, String name, String orgHandle, int depth) {

        this.id = id;
        this.name = name;
        this.orgHandle = orgHandle;
        this.depth = depth;
    }

    public String getId() {

        return id;
    }

    public String getName() {

        return name;
    }

    public String getOrgHandle() {

        return orgHandle;
    }

    public int getDepth() {

        return depth;
    }
}
