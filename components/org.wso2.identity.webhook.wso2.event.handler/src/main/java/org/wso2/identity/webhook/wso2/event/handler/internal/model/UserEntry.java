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

import com.fasterxml.jackson.annotation.JsonInclude;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;

import java.util.List;

/**
 * User entry in a role membership list. Carries the user's id, the user-store domain,
 * and a list of claims (e.g. username, agent name). Agents — identified by their
 * user-store — surface additional identifiers as claims rather than a separate
 * representation.
 */
public class UserEntry {

    private String id;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String userStoreDomain;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<UserClaim> claims;

    public UserEntry(String id, String userStoreDomain, List<UserClaim> claims) {

        this.id = id;
        this.userStoreDomain = userStoreDomain;
        this.claims = claims;
    }

    public String getId() {

        return id;
    }

    public String getUserStoreDomain() {

        return userStoreDomain;
    }

    public List<UserClaim> getClaims() {

        return claims;
    }
}
