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

package org.wso2.identity.webhook.wso2.event.handler.internal.model;

/**
 * Group entry in a role membership list, carrying id, group name (without user-store prefix),
 * and the user-store domain the group belongs to.
 */
public class GroupEntry {

    private String id;
    private String groupName;
    private String userStoreDomain;

    public GroupEntry(String id, String groupName, String userStoreDomain) {

        this.id = id;
        this.groupName = groupName;
        this.userStoreDomain = userStoreDomain;
    }

    public String getId() {

        return id;
    }

    public String getGroupName() {

        return groupName;
    }

    public String getUserStoreDomain() {

        return userStoreDomain;
    }
}
