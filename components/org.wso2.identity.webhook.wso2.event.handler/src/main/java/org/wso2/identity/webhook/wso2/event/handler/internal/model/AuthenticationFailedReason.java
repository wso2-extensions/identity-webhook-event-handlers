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

package org.wso2.identity.webhook.wso2.event.handler.internal.model;

/**
 * Authentication failed reason class.
 */
public class AuthenticationFailedReason {

    private String id;
    private FailedStep failedStep;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public FailedStep getFailedStep() {
        return failedStep;
    }

    public void setFailedStep(FailedStep failedStep) {
        this.failedStep = failedStep;
    }

    /**
     * Failed step class.
     */
    public static class FailedStep {
        private int step;
        private String idp;
        private String authenticator;

        public int getStep() {
            return step;
        }

        public void setStep(int step) {
            this.step = step;
        }

        public String getIdp() {
            return idp;
        }

        public void setIdp(String idp) {
            this.idp = idp;
        }

        public String getAuthenticator() {
            return authenticator;
        }

        public void setAuthenticator(String authenticator) {
            this.authenticator = authenticator;
        }
    }
}
