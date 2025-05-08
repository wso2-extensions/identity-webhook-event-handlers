package org.wso2.identity.webhook.caep.event.handler;

import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.api.builder.CAEPVerificationEventPayloadBuilder;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPVerificationEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

public class CAEPVerificationEventPayloadBuilderTest {

    @InjectMocks
    private CAEPVerificationEventPayloadBuilder caepVerificationEventPayloadBuilder;

    @BeforeClass
    public void setUp() {

        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetEventSchemaType() {

        EventSchema eventSchema = caepVerificationEventPayloadBuilder.getEventSchemaType();
        assertNotNull(eventSchema);
        assertEquals(eventSchema, EventSchema.CAEP);
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

}
