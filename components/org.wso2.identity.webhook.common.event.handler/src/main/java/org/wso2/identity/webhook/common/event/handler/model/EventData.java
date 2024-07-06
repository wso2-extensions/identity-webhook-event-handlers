/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.model;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model.AuthenticationData;

import java.util.List;

public class EventData {

    private AuthenticationData<?, ?> authenticationData;
    private AuthenticatedUser authenticatedUser;
    private AuthStep failedStep;
    private List<AuthStep> authSteps;
    private AuthenticationContext authenticationContext;
    private String tenantDomain;

    public EventData(AuthenticationData<?, ?> authenticationData, AuthenticatedUser authenticatedUser,
                     AuthStep failedStep, List<AuthStep> authSteps, AuthenticationContext authenticationContext,
                     String tenantDomain) {

        this.authenticationData = authenticationData;
        this.authenticatedUser = authenticatedUser;
        this.failedStep = failedStep;
        this.authSteps = authSteps;
        this.authenticationContext = authenticationContext;
        this.tenantDomain = tenantDomain;
    }

    public EventData() {
    }

    public AuthenticationData<?, ?> getAuthenticationData() {
        return authenticationData;
    }

    public void setAuthenticationData(AuthenticationData<?, ?> authenticationData) {

        this.authenticationData = authenticationData;
    }

    public AuthenticatedUser getAuthenticatedUser() {
        return authenticatedUser;
    }

    public void setAuthenticatedUser(AuthenticatedUser authenticatedUser) {

        this.authenticatedUser = authenticatedUser;
    }

    public AuthStep getFailedStep() {
        return failedStep;
    }

    public void setFailedStep(AuthStep failedStep) {
        this.failedStep = failedStep;
    }

    public List<AuthStep> getAuthSteps() {
        return authSteps;
    }

    public void setAuthSteps(List<AuthStep> authSteps) {
        this.authSteps = authSteps;
    }

    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }
    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }
}
