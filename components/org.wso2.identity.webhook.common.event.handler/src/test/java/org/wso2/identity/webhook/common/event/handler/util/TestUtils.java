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

package org.wso2.identity.webhook.common.event.handler.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import static org.mockito.Mockito.*;
import static org.testng.Assert.assertEquals;

/**
 * Common utility methods for tests.
 */
public class TestUtils {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final int SAMPLE_TENANT_ID = 100;
    private static MockedStatic<ServiceURLBuilder> mockedStaticServiceURLBuilder;
    private static MockedStatic<IdentityTenantUtil> mockedStaticIdentityTenantUtil;

    /**
     * Mocks the ServiceURLBuilder.
     */
    public static void mockServiceURLBuilder() {

        ServiceURLBuilder builder = new ServiceURLBuilder() {
            String path = "";
            @Override
            public ServiceURLBuilder addPath(String... strings) {

                Arrays.stream(strings).forEach(x -> {
                    path += "/" + x;
                });
                return this;
            }

            @Override
            public ServiceURLBuilder addParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURLBuilder setFragment(String s) {

                return this;
            }

            @Override
            public ServiceURLBuilder addFragmentParameter(String s, String s1) {

                return this;
            }

            @Override
            public ServiceURL build() {

                ServiceURL serviceURL = mock(ServiceURL.class);
                when(serviceURL.getAbsolutePublicURL()).thenReturn("https://localhost:9443" + path);
                when(serviceURL.getRelativePublicURL()).thenReturn(path);
                when(serviceURL.getRelativeInternalURL()).thenReturn(path);
                return serviceURL;
            }
        };

        mockedStaticServiceURLBuilder = mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(builder);
    }

    /**
     * Closes the mocked ServiceURLBuilder.
     */
    public static void closeMockedServiceURLBuilder() {

        mockedStaticServiceURLBuilder.close();

    }

    /**
     * Mocks the IdentityTenantUtil.
     */
    public static void mockIdentityTenantUtil() {
        mockedStaticIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(SAMPLE_TENANT_DOMAIN)).thenReturn(SAMPLE_TENANT_ID);

    }

    /**
     * Closes the mocked IdentityTenantUtil.
     */
    public static void closeMockedIdentityTenantUtil() {

        mockedStaticIdentityTenantUtil.close();

    }

    /**
     * Reads the sample event schemas from the resources.
     *
     * @return Sample event schemas.
     * @throws IOException    If an error occurs while reading the file.
     * @throws ParseException If an error occurs while parsing the JSON.
     */
    public static JSONObject getEventSchemas() throws IOException, ParseException {

        String resourceFilePath = new File("src/test/resources/sample-event-configs.json").getAbsolutePath();
        JSONParser jsonParser = new JSONParser();
        return (JSONObject) jsonParser.parse(new InputStreamReader(
                Files.newInputStream(Paths.get(resourceFilePath)), StandardCharsets.UTF_8));
    }

    /**
     * Asserts the events getting published.
     *
     * @param mockedWebSubHubAdapterService Mocked WebSubHubAdapterService.
     * @param expectedEventPayload          Expected event payload.
     * @param eventSchemaUri                Event schema URI.
     * @throws IOException If an error occurs while converting the payload to JSON.
     */
    public static void assertEventsGettingPublished(EventPublisherService mockedWebSubHubAdapterService,
                                                    SecurityEventTokenPayload expectedEventPayload,
                                                    EventContext eventSchemaUri)
            throws IOException {

        ObjectMapper mapper = new ObjectMapper();
        String expectedJSONString = mapper.writeValueAsString(expectedEventPayload);
        org.json.JSONObject expectedJSONObject = new org.json.JSONObject(expectedJSONString);

        ArgumentCaptor<EventContext> eventUriArgumentCaptor = ArgumentCaptor.forClass(EventContext.class);
        ArgumentCaptor<SecurityEventTokenPayload> eventPayloadArgumentCaptor =
                ArgumentCaptor.forClass(SecurityEventTokenPayload.class);

        verify(mockedWebSubHubAdapterService).publish(eventPayloadArgumentCaptor.capture(),
                eventUriArgumentCaptor.capture());

        ObjectMapper responseMapper = new ObjectMapper();
        String responseJSONString = responseMapper.writeValueAsString(eventPayloadArgumentCaptor.getValue());
        org.json.JSONObject responseJSONObject = new org.json.JSONObject(responseJSONString);

        assertEquals(responseJSONObject.toString(), expectedJSONObject.toString());
        assertEquals(eventUriArgumentCaptor.getValue(), eventSchemaUri);
    }
}
