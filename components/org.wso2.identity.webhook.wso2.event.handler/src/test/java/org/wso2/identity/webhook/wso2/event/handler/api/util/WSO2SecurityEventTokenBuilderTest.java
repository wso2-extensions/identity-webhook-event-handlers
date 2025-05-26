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

package org.wso2.identity.webhook.wso2.event.handler.api.util;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import static org.testng.Assert.assertEquals;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

public class WSO2SecurityEventTokenBuilderTest {

    @Mock
    private EventPayload eventPayload;
    @Mock
    private EventData eventData;
    @InjectMocks
    private WSO2SecurityEventTokenBuilder wso2SecurityEventTokenBuilder;

    @BeforeClass
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        mockIdentityTenantUtil();
        mockServiceURLBuilder();
    }

    @AfterClass
    public void tearDown() {
        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    @Test
    public void testGetEventSchema() {

        assertEquals(wso2SecurityEventTokenBuilder.getEventSchema(), EventSchema.WSO2);
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testBuildSecurityEventTokenPayloadWithNullEventPayload() throws  IdentityEventException {

        wso2SecurityEventTokenBuilder.buildSecurityEventTokenPayload(null, "eventUri", eventData);
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testBuildSecurityEventTokenPayloadWithEmptyEventUri() throws IdentityEventException {

        wso2SecurityEventTokenBuilder.buildSecurityEventTokenPayload(eventPayload, "", eventData);
    }

    @Test
    public void testBuildSecurityEventTokenPayloadWithNullEventData() throws IdentityEventException {

        wso2SecurityEventTokenBuilder.buildSecurityEventTokenPayload(eventPayload, "eventUri", null);
        // No exception should be thrown, the method should complete successfully.
    }

    @Test
    public void testBuildSecurityEventTokenPayload() throws IdentityEventException {

        String eventUri = "eventUri";

        SecurityEventTokenPayload securityEventTokenPayload =
                wso2SecurityEventTokenBuilder.buildSecurityEventTokenPayload(eventPayload, eventUri, eventData);

        assertEquals(securityEventTokenPayload.getIss(), "https://localhost:9443/t/myorg");
        assertEquals(securityEventTokenPayload.getJti().length(), 36);
        assertEquals(securityEventTokenPayload.getEvents().size(), 1);
        assertEquals(securityEventTokenPayload.getEvents().get(eventUri), eventPayload);
    }
}
