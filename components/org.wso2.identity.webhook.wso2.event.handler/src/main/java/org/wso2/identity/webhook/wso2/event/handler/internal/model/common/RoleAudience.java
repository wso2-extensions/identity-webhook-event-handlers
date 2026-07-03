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
 * Represents the audience scoping of a V2 role.
 * The audience can be an ORGANIZATION or an APPLICATION.
 */
public class RoleAudience {

    private String type;
    private String value;
    private String display;

    public RoleAudience() {

    }

    public RoleAudience(String type, String value, String display) {

        this.type = type;
        this.value = value;
        this.display = display;
    }

    public String getType() {

        return type;
    }

    public void setType(String type) {

        this.type = type;
    }

    public String getValue() {

        return value;
    }

    public void setValue(String value) {

        this.value = value;
    }

    public String getDisplay() {

        return display;
    }

    public void setDisplay(String display) {

        this.display = display;
    }
}
