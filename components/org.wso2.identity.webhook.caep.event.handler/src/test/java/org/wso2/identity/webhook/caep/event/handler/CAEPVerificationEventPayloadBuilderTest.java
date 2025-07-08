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

package org.wso2.identity.webhook.caep.event.handler;

import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.api.builder.CAEPVerificationEventPayloadBuilder;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPVerificationEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit test class for {@link CAEPVerificationEventPayloadBuilder}.
 */
public class CAEPVerificationEventPayloadBuilderTest {

    @InjectMocks
    private CAEPVerificationEventPayloadBuilder caepVerificationEventPayloadBuilder;

    @BeforeClass
    public void setUp() {

        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetEventSchemaType() {

        Constants.EventSchema eventSchema = caepVerificationEventPayloadBuilder.getEventSchemaType();
        assertNotNull(eventSchema);
        assertEquals(eventSchema, Constants.EventSchema.CAEP);
    }

    @Test
    public void testBuildVerificationEventPayload() {

        String state = "state";
        String streamId = "streamId";

        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put("state", state);
        eventParams.put("streamId", streamId);

        EventData eventData = EventData.builder().eventParams(eventParams).build();

        EventPayload payload = caepVerificationEventPayloadBuilder.buildVerificationEventPayload(eventData);

        assertTrue(payload instanceof CAEPVerificationEventPayload);
        assertEquals(((CAEPVerificationEventPayload) payload).getState(), state);
    }

    @Test
    public void testBuildVerificationEventPayloadWithoutState() {

        String streamId = "streamId";

        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put("streamId", streamId);

        EventData eventData = EventData.builder().eventParams(eventParams).build();

        EventPayload payload = caepVerificationEventPayloadBuilder.buildVerificationEventPayload(eventData);

        assertTrue(payload instanceof CAEPVerificationEventPayload);
        assertEquals(((CAEPVerificationEventPayload) payload).getState(), null);
    }
}
