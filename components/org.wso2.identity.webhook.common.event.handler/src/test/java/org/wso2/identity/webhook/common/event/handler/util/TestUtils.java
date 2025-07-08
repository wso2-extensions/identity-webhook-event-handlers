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

package org.wso2.identity.webhook.common.event.handler.util;

import org.mockito.MockedStatic;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

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

                Arrays.stream(strings).forEach(x -> path += "/" + x);
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

        if (mockedStaticServiceURLBuilder != null && !mockedStaticServiceURLBuilder.isClosed()) {
            mockedStaticServiceURLBuilder.close();
        }
    }

    /**
     * Mocks the IdentityTenantUtil.
     */
    public static void mockIdentityTenantUtil() {

        mockedStaticIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantedSessionsEnabled()).thenReturn(false);
        when(IdentityTenantUtil.getTenantId(SAMPLE_TENANT_DOMAIN)).thenReturn(SAMPLE_TENANT_ID);
    }

    /**
     * Closes the mocked IdentityTenantUtil.
     */
    public static void closeMockedIdentityTenantUtil() {

        if (mockedStaticIdentityTenantUtil != null && !mockedStaticIdentityTenantUtil.isClosed()) {
            mockedStaticIdentityTenantUtil.close();
        }
    }
}
