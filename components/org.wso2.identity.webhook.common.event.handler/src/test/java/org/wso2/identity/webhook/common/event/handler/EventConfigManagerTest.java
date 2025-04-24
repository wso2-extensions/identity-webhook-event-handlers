package org.wso2.identity.webhook.common.event.handler;

import org.mockito.MockedStatic;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.util.TestUtils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;

public class EventConfigManagerTest {

    private EventConfigManager eventConfigManager;
    private static MockedStatic<Files> mockedFiles;

    @BeforeClass
    public void setup() throws IdentityEventServerException {

        TestUtils.mockServiceURLBuilder();
        TestUtils.mockIdentityTenantUtil();

        String fakeJsonContent = "{ \"events\": { \"validEvent\": { \"eventSchema\": " +
                "\"https://schemas.example.com/event\" } } }";
        mockFilesNewInputStream(fakeJsonContent);
        eventConfigManager = EventConfigManager.getInstance();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        closeMockedFiles();
    }

    @Test
    public void testGetEventUriWithValidEvent() throws IdentityEventServerException {

        String eventUri = eventConfigManager.getEventUri("validEvent");
        assertEquals(eventUri, "https://schemas.example.com/event",
                "The event URI should match the expected URI.");
    }

    @Test(dependsOnMethods = "testGetEventUriWithValidEvent", expectedExceptions = IdentityEventServerException.class)
    public void testGetEventUriWithMissingSchemaKey() throws IdentityEventServerException, NoSuchFieldException,
            IllegalAccessException {

        resetEventConfigManagerInstance();
        String invalidJsonContent = "{ \"events\": { \"validEvent\": {} } }";
        closeMockedFiles();
        mockFilesNewInputStream(invalidJsonContent);
        eventConfigManager = EventConfigManager.getInstance();
        eventConfigManager.getEventUri("validEvent");
    }

    @Test(expectedExceptions = IdentityEventServerException.class)
    public void testGetEventUriWithInvalidEvent() throws IdentityEventServerException {

        eventConfigManager.getEventUri("invalidEvent");
    }

    @Test
    public void testExtractEventPublisherConfig() throws IdentityEventException {

        Resources resources = createResourcesWithAttributes(Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT,
                "{\"publishEnabled\":true}");
        EventPublisherConfig config = eventConfigManager.extractEventPublisherConfig(resources,
                IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        assertTrue(config.isPublishEnabled(), "Publish should be enabled.");
    }

    @Test
    public void testExtractEventPublisherConfigWithEmptyResources() throws IdentityEventException {

        Resources resources = new Resources();
        resources.setResources(new ArrayList<>());
        EventPublisherConfig config = eventConfigManager.extractEventPublisherConfig(resources,
                Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT);
        assertFalse(config.isPublishEnabled(), "Publish should be disabled for empty resources.");
    }

    @Test
    public void testExtractEventPublisherConfigWithNoAttributes() throws IdentityEventException {

        Resources resources = createResourcesWithNoAttributes();
        EventPublisherConfig config = eventConfigManager.extractEventPublisherConfig(resources,
                Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT);
        assertFalse(config.isPublishEnabled(), "Publish should be disabled when there are no attributes.");
    }

    @Test
    public void testPublishEnabledValue() throws IdentityEventException {

        Resources resources = createResourcesWithAttributes(Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT,
                "{\"publishEnabled\":true}");
        EventPublisherConfig config = eventConfigManager.extractEventPublisherConfig(resources,
                IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        assertTrue(config.isPublishEnabled(), "Publish should be enabled.");

        resources = createResourcesWithAttributes(Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT,
                "{\"publishEnabled\":false}");
        config = eventConfigManager.extractEventPublisherConfig(resources,
                IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        assertFalse(config.isPublishEnabled(), "Publish should be disabled.");
    }

    @Test
    public void testResourceConfigValues() throws IdentityEventException {

        Resources resources = createResourcesWithAttributes(Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT,
                "{ \"properties\": { \"property1\": \"value1\", \"property2\": \"value2\" } }");
        EventPublisherConfig config = eventConfigManager.extractEventPublisherConfig(resources,
                IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        assertEquals(config.getProperties().getConfigs().get("property1"), "value1", "properties" +
                " should match the expected value.");
        assertEquals(config.getProperties().getConfigs().get("property2"), "value2", "properties" +
                " should match the " +
                "expected value.");
    }

    private void resetEventConfigManagerInstance() throws NoSuchFieldException, IllegalAccessException {

        Field instance = EventConfigManager.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    private Resources createResourcesWithAttributes(String eventKey, String attributeValue) {

        Resources resources = new Resources();
        List<Resource> resourceList = new ArrayList<>();
        Resource resource = new Resource();

        List<Attribute> attributeList = new ArrayList<>();
        Attribute attribute = new Attribute(eventKey, attributeValue);
        attributeList.add(attribute);
        resource.setAttributes(attributeList);
        resourceList.add(resource);
        resources.setResources(resourceList);
        return resources;
    }

    private Resources createResourcesWithNoAttributes() {
        Resources resources = new Resources();
        List<Resource> resourceList = new ArrayList<>();
        Resource resource = new Resource();
        resource.setAttributes(new ArrayList<>());
        resourceList.add(resource);
        resources.setResources(resourceList);
        return resources;
    }

    private void mockFilesNewInputStream(String jsonContent) {

        InputStream inputStream = new ByteArrayInputStream(jsonContent.getBytes(StandardCharsets.UTF_8));
        mockedFiles = mockStatic(Files.class);
        mockedFiles.when(() -> Files.newInputStream(any(Path.class))).thenReturn(inputStream);
    }

    private void closeMockedFiles() {

        mockedFiles.reset();
        if (mockedFiles != null) {
            mockedFiles.close();
        }
    }
}
