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

package org.wso2.identity.webhook.wso2.event.handler.internal.model.common;

import java.util.Date;
import java.util.List;

/**
 * This class represents a session.
 */
public class Session {

    private final String id;
    private final Date loginTime;
    private final List<Application> applications;

    private Session(Builder builder) {

        this.id = builder.id;
        this.loginTime = builder.loginTime;
        this.applications = builder.applications;
    }

    public String getId() {
        return id;
    }

    public Date getLoginTime() {

        return loginTime;
    }

    public List<Application> getApplications() {
        return applications;
    }

    public static class Builder {

        private String id;
        private Date loginTime;
        private List<Application> applications;

        public Builder id(String id) {

            this.id = id;
            return this;
        }

        public Builder loginTime(Date loginTime) {

            this.loginTime = loginTime;
            return this;
        }

        public Builder applications(List<Application> applications) {

            this.applications = applications;
            return this;
        }

        public Session build() {

            return new Session(this);
        }
    }
}
