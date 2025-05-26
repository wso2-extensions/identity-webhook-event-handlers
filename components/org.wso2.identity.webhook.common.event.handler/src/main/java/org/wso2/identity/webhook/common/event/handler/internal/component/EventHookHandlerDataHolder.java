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

package org.wso2.identity.webhook.common.event.handler.internal.component;

import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.VerificationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.util.SecurityEventTokenBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * A data holder class to keep the data of the event handler component.
 */
public class EventHookHandlerDataHolder {

    private static final EventHookHandlerDataHolder instance = new EventHookHandlerDataHolder();
    private ConfigurationManager configurationManager;
    private EventPublisherService eventPublisherService;
    private final List<LoginEventPayloadBuilder> loginEventPayloadBuilders = new ArrayList<>();
    private final List<UserOperationEventPayloadBuilder> userOperationEventPayloadBuilders = new ArrayList<>();
    private final List<SessionEventPayloadBuilder> sessionEventPayloadBuilders = new ArrayList<>();
    private final List<CredentialEventPayloadBuilder> credentialEventPayloadBuilders = new ArrayList<>();
    private final List<VerificationEventPayloadBuilder> verificationEventPayloadBuilders = new ArrayList<>();
    private final List<SecurityEventTokenBuilder> securityEventTokenBuilders = new ArrayList<>();

    private EventHookHandlerDataHolder() {

    }

    public static EventHookHandlerDataHolder getInstance() {

        return instance;
    }

    /**
     * Get the list of security event token builders available.
     *
     * @return List of security event token builders.
     */
    public List<SecurityEventTokenBuilder> getSecurityEventTokenBuilders() {

        return securityEventTokenBuilders;
    }

    /**
     * Add a security event token builder to the list.
     *
     * @param securityEventTokenBuilder A security event token builder.
     */
    public void addSecurityEventTokenBuilder(SecurityEventTokenBuilder securityEventTokenBuilder) {

        securityEventTokenBuilders.add(securityEventTokenBuilder);
    }

    /**
     * Remove a security event token builder from the list.
     *
     * @param securityEventTokenBuilder A security event token builder.
     */
    public void removeSecurityEventTokenBuilder(SecurityEventTokenBuilder securityEventTokenBuilder) {

        securityEventTokenBuilders.remove(securityEventTokenBuilder);
    }

    /**
     * Get the list of verification event payload builder implementations available.
     *
     * @return List of verification event payload builder implementations.
     */
    public List<VerificationEventPayloadBuilder> getVerificationEventPayloadBuilders() {

        return verificationEventPayloadBuilders;
    }

    /**
     * Add a verification event payload builder to the list.
     *
     * @param verificationEventPayloadBuilder A verification event payload builders.
     */
    public void addVerificationEventPayloadBuilder(VerificationEventPayloadBuilder verificationEventPayloadBuilder) {

        verificationEventPayloadBuilders.add(verificationEventPayloadBuilder);
    }

    /**
     * Remove a verification event payload builder from the list.
     *
     * @param verificationEventPayloadBuilder A verification event payload builders.
     */
    public void removeVerificationEventPayloadBuilder(VerificationEventPayloadBuilder verificationEventPayloadBuilder) {

        verificationEventPayloadBuilders.remove(verificationEventPayloadBuilder);
    }

    /**
     * Get the list of credential event payload builder implementations available.
     *
     * @return List of credential event payload builder implementations.
     */
    public List<CredentialEventPayloadBuilder> getCredentialEventPayloadBuilders() {

        return credentialEventPayloadBuilders;
    }

    /**
     * Add a credential event payload builder to hte list.
     *
     * @param credentialEventPayloadBuilder A credential event payload builders.
     */
    public void addCredentialEventPayloadBuilder(CredentialEventPayloadBuilder credentialEventPayloadBuilder) {

        credentialEventPayloadBuilders.add(credentialEventPayloadBuilder);
    }

    /**
     * Remove a credential event payload builder from the list.
     *
     * @param credentialEventPayloadBuilder A credential event payload builders.
     */
    public void removeCredentialEventPayloadBuilder(CredentialEventPayloadBuilder credentialEventPayloadBuilder) {

        credentialEventPayloadBuilders.remove(credentialEventPayloadBuilder);
    }

    /**
     * Get the list of session event payload builder implementations available.
     *
     * @return List of session event payload builder implementations.
     */
    public List<SessionEventPayloadBuilder> getSessionEventPayloadBuilders() {

        return sessionEventPayloadBuilders;
    }

    /**
     * Add session event payload builder implementation.
     *
     * @param sessionEventPayloadBuilder Session event payload builder implementation.
     */
    public void addSessionEventPayloadBuilder(SessionEventPayloadBuilder sessionEventPayloadBuilder) {

        sessionEventPayloadBuilders.add(sessionEventPayloadBuilder);
    }

    /**
     * Remove session event payload builder implementation.
     *
     * @param sessionEventPayloadBuilder Session event payload builder implementation.
     */
    public void removeSessionEventPayloadBuilder(SessionEventPayloadBuilder sessionEventPayloadBuilder) {

        sessionEventPayloadBuilders.remove(sessionEventPayloadBuilder);
    }

    /**
     * Get the list of login event payload builder implementations available.
     *
     * @return List of login event payload builder implementations.
     */
    public List<LoginEventPayloadBuilder> getLoginEventPayloadBuilders() {

        return loginEventPayloadBuilders;
    }

    /**
     * Add login event payload builder implementation.
     *
     * @param loginEventPayloadBuilder Login event payload builder implementation.
     */
    public void addLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        loginEventPayloadBuilders.add(loginEventPayloadBuilder);
    }

    /**
     * Remove login event payload builder implementation.
     *
     * @param loginEventPayloadBuilder Login event payload builder implementation.
     */
    public void removeLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        loginEventPayloadBuilders.remove(loginEventPayloadBuilder);
    }

    public List<UserOperationEventPayloadBuilder> getUserOperationEventPayloadBuilders() {

        return userOperationEventPayloadBuilders;
    }

    /**
     * Add User operation event payload builder implementation.
     *
     * @param userOperationEventPayloadBuilder User operation event payload builder implementation.
     */
    public void addUserOperationEventPayloadBuilder(UserOperationEventPayloadBuilder userOperationEventPayloadBuilder) {

        userOperationEventPayloadBuilders.add(userOperationEventPayloadBuilder);
    }

    /**
     * Remove User operation event payload builder implementation.
     *
     * @param userOperationEventPayloadBuilder User operation event payload builder implementation.
     */
    public void removeUserOperationEventPayloadBuilder(
            UserOperationEventPayloadBuilder userOperationEventPayloadBuilder) {

        userOperationEventPayloadBuilders.remove(userOperationEventPayloadBuilder);
    }

    /**
     * Set the configuration manager.
     *
     * @param configurationManager Configuration manager.
     */
    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }

    /**
     * Get the configuration manager.
     *
     * @return Configuration manager.
     */
    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }

    /**
     * Get the event publisher service.
     *
     * @return Event publisher service.
     */
    public EventPublisherService getEventPublisherService() {

        return eventPublisherService;
    }

    /**
     * Set the event publisher service.
     *
     * @param eventPublisherService Event publisher service.
     */
    public void setEventPublisherService(EventPublisherService eventPublisherService) {

        this.eventPublisherService = eventPublisherService;
    }
}
