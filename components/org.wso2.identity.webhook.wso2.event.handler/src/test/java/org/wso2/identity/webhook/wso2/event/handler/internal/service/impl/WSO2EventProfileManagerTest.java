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

package org.wso2.identity.webhook.wso2.event.handler.internal.service.impl;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;

import static org.testng.Assert.assertEquals;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.CREDENTIAL_CHANGE_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UPDATE_USER_CREDENTIAL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;

/**
 * Unit tests for {@link WSO2EventProfileManager}.
 */
public class WSO2EventProfileManagerTest {

    private WSO2EventProfileManager wso2EventProfileManager;
    private MockedStatic<IdentityContext> identityContextMockedStatic;
    private IdentityContext mockIdentityContext;

    @BeforeMethod
    public void setUp() {

        wso2EventProfileManager = new WSO2EventProfileManager();
        identityContextMockedStatic = Mockito.mockStatic(IdentityContext.class);
        mockIdentityContext = Mockito.mock(IdentityContext.class);
        identityContextMockedStatic.when(IdentityContext::getThreadLocalIdentityContext)
                .thenReturn(mockIdentityContext);
    }

    @AfterMethod
    public void tearDown() {

        if (identityContextMockedStatic != null) {
            identityContextMockedStatic.close();
        }
    }

    @DataProvider(name = "credentialUpdateEventDataProvider")
    public Object[][] credentialUpdateEventDataProvider() {

        return new Object[][]{
                {IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM},
                {IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_ME_API}
        };
    }

    @Test(dataProvider = "credentialUpdateEventDataProvider")
    public void testResolveEventMetadataForCredentialUpdateEvents(String eventName) {

        Mockito.when(mockIdentityContext.getCurrentFlow()).thenReturn(null);

        EventMetadata eventMetadata = wso2EventProfileManager.resolveEventMetadata(eventName);

        assertEquals(eventMetadata.getChannel(), CREDENTIAL_CHANGE_CHANNEL);
        assertEquals(eventMetadata.getEvent(), POST_UPDATE_USER_CREDENTIAL);
        assertEquals(eventMetadata.getEventProfile(), WSO2.name());
    }
}
