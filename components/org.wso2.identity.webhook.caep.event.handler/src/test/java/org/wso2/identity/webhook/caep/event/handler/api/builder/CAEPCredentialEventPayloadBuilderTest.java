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

package org.wso2.identity.webhook.caep.event.handler.api.builder;

import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.constants.Constants;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPCredentialChangeEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class CAEPCredentialEventPayloadBuilderTest {

    @InjectMocks
    private CAEPCredentialEventPayloadBuilder caepCredentialEventPayloadBuilder;

    @BeforeClass
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testBuildUpdatePasswordByUser() {

        EventData eventData = mock(EventData.class);
        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(Constants.EVENT_TIMESTAMP, "1234567890");
        when(eventData.getEventParams()).thenReturn(eventParams);

        EventPayload eventPayload = caepCredentialEventPayloadBuilder.buildUpdatePasswordByUser(eventData);

        assertNotNull(eventPayload);
        assertTrue(eventPayload instanceof CAEPCredentialChangeEventPayload);
        CAEPCredentialChangeEventPayload caepCredentialChangeEventPayload = (CAEPCredentialChangeEventPayload) eventPayload;
        assertEquals(caepCredentialChangeEventPayload.getEventTimeStamp(), 1234567890L);
        assertEquals(caepCredentialChangeEventPayload.getInitiatingEntity(), "user");
        assertEquals(caepCredentialChangeEventPayload.getReasonAdmin().get("en"), "Password Update by User");
        assertEquals(caepCredentialChangeEventPayload.getReasonUser().get("en"), "Password Changed by User");
        assertEquals(caepCredentialChangeEventPayload.getCredentialType(), "password");
        assertEquals(caepCredentialChangeEventPayload.getChangeType(),
                CAEPCredentialChangeEventPayload.ChangeType.UPDATE);
        assertEquals(caepCredentialChangeEventPayload.getFriendlyName(), "Password");
    }

    @Test
    public void testBuildUpdatePasswordByAdmin() {

        EventData eventData = mock(EventData.class);
        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(Constants.EVENT_TIMESTAMP, "1234567890");
        when(eventData.getEventParams()).thenReturn(eventParams);

        EventPayload eventPayload = caepCredentialEventPayloadBuilder.buildUpdatePasswordByAdmin(eventData);

        assertNotNull(eventPayload);
        assertTrue(eventPayload instanceof CAEPCredentialChangeEventPayload);
        CAEPCredentialChangeEventPayload caepCredentialChangeEventPayload = (CAEPCredentialChangeEventPayload) eventPayload;
        assertEquals(caepCredentialChangeEventPayload.getEventTimeStamp(), 1234567890L);
        assertEquals(caepCredentialChangeEventPayload.getInitiatingEntity(), "admin");
        assertEquals(caepCredentialChangeEventPayload.getReasonAdmin().get("en"), "Password Update by Admin");
        assertEquals(caepCredentialChangeEventPayload.getReasonUser().get("en"), "Password Changed by Admin");
        assertEquals(caepCredentialChangeEventPayload.getCredentialType(), "password");
        assertEquals(caepCredentialChangeEventPayload.getChangeType(),
                CAEPCredentialChangeEventPayload.ChangeType.UPDATE);
        assertEquals(caepCredentialChangeEventPayload.getFriendlyName(), "Password");
    }

    @DataProvider(name = "flowDataProvider")
    public Object[][] flowDataProvider() {
        return new Object[][]{
                {Flow.InitiatingPersona.USER, "user"},
                {Flow.InitiatingPersona.ADMIN, "admin"},
                {Flow.InitiatingPersona.SYSTEM, "policy"},
                {Flow.InitiatingPersona.APPLICATION, "system"}
        };
    }

    @Test(dataProvider = "flowDataProvider")
    public void testBuildAddNewPassword(Flow.InitiatingPersona initiatingPersona, String expectedInitiatingEntity) {

        EventData eventData = mock(EventData.class);
        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(Constants.EVENT_TIMESTAMP, "1234567890");
        when(eventData.getEventParams()).thenReturn(eventParams);
        Flow flow = mock(Flow.class);
        when(eventData.getFlow()).thenReturn(flow);
        when(flow.getInitiatingPersona()).thenReturn(initiatingPersona);

        EventPayload eventPayload = caepCredentialEventPayloadBuilder.buildAddNewPassword(eventData);

        assertNotNull(eventPayload);
        assertTrue(eventPayload instanceof CAEPCredentialChangeEventPayload);
        CAEPCredentialChangeEventPayload caepCredentialChangeEventPayload = (CAEPCredentialChangeEventPayload)
                eventPayload;
        assertEquals(caepCredentialChangeEventPayload.getEventTimeStamp(), 1234567890L);
        assertEquals(caepCredentialChangeEventPayload.getInitiatingEntity(), expectedInitiatingEntity);
        assertEquals(caepCredentialChangeEventPayload.getReasonAdmin().get("en"), "Create new password");
        assertEquals(caepCredentialChangeEventPayload.getReasonUser().get("en"), "Created a new password");
        assertEquals(caepCredentialChangeEventPayload.getCredentialType(), "password");
        assertEquals(caepCredentialChangeEventPayload.getChangeType(),
                CAEPCredentialChangeEventPayload.ChangeType.CREATE);
        assertEquals(caepCredentialChangeEventPayload.getFriendlyName(), "Password");
    }


}
