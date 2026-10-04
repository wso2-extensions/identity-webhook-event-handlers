/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.identity.webhook.wso2.event.handler.internal.util;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

/**
 * Tests the handling of user store failures while populating user claims.
 */
public class WSO2PayloadUtilsTest {

    private static final String TENANT_DOMAIN = "myorg";
    private static final int TENANT_ID = 100;
    private static final String USER_ID = "4f0d5b9c-0a2e-4f9a-9f1d-6f0a2b3c4d5e";
    private static final String NON_EXISTING_USER_CODE = "30007";
    private static final String ERROR_LOG_PREFIX = "Error while retrieving user claims for user";

    @Mock
    private RealmService realmService;

    @Mock
    private UserRealm userRealm;

    @Mock
    private UniqueIDUserStoreManager userStoreManager;

    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;

    @BeforeClass
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(realmService);
        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
    }

    @AfterClass
    public void tearDown() {

        if (identityTenantUtilMockedStatic != null) {
            identityTenantUtilMockedStatic.close();
        }
    }

    /**
     * A user store manager that sets the error code on the exception.
     */
    @Test
    public void testMissingUserWithErrorCodeIsNotLoggedAsAnError() throws Exception {

        UserStoreException withCode = new UserStoreException(
                NON_EXISTING_USER_CODE + " - UserNotFound: User " + USER_ID + " does not exist in: PRIMARY",
                NON_EXISTING_USER_CODE);
        assertMissingUserIsNotAnError(withCode);
    }

    /**
     * Released user store managers throw the non existing user failure through the single argument
     * constructor, which leaves the error code field null and carries the code only as a prefix of
     * the message. The guard has to recognise that form too.
     */
    @Test
    public void testMissingUserWithErrorCodeOnlyInMessageIsNotLoggedAsAnError() throws Exception {

        UserStoreException codeInMessageOnly = new UserStoreException(
                NON_EXISTING_USER_CODE + " - UserNotFound: User " + USER_ID + " does not exist in: PRIMARY");
        assertMissingUserIsNotAnError(codeInMessageOnly);
    }

    /**
     * Any other user store failure is a server side problem and must still be logged as an error.
     */
    @Test
    public void testOtherUserStoreFailureIsStillLoggedAsAnError() throws Exception {

        doThrow(new UserStoreException("Error occurred while getting database type from DB connection"))
                .when(userStoreManager).getUserClaimValuesWithID(any(), any(), any());

        String logged = capturePopulateUserClaims();
        assertTrue(logged.contains(ERROR_LOG_PREFIX),
                "A user store failure that is not a missing user must still be logged as an error, but was: "
                        + logged);
    }

    private void assertMissingUserIsNotAnError(UserStoreException thrown) throws Exception {

        doThrow(thrown).when(userStoreManager).getUserClaimValuesWithID(any(), any(), any());

        String logged = capturePopulateUserClaims();
        // The debug line proves the logger is reaching the captured stream. Without it, an empty
        // capture would make the assertion below pass for the wrong reason.
        assertTrue(logged.contains("does not exist in tenant"),
                "Expected the missing user to be reported at debug level, but captured: " + logged);
        assertFalse(logged.contains(ERROR_LOG_PREFIX),
                "A missing user is a client side condition and must not be logged as an error, but was: " + logged);
    }

    private String capturePopulateUserClaims() {

        PrintStream originalOut = System.out;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured));
        try {
            WSO2PayloadUtils.populateUserClaims(new User(), USER_ID, TENANT_DOMAIN);
        } finally {
            System.setOut(originalOut);
        }
        return captured.toString();
    }
}
