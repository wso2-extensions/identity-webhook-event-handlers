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

package org.wso2.identity.webhook.caep.event.handler.internal.model;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Unit test class for CAEP event payload models.
 */
public class CAEPEventPayloadModelTest {

    private static final Map<String, String> sampleReasonAdmin = new HashMap<>();
    private static final Map<String, String> sampleReasonUser = new HashMap<>();
    private static final String initiatingEntity = "admin";
    private static final long eventTimeStamp = System.currentTimeMillis();

    @BeforeClass
    public void setUp() {

        sampleReasonAdmin.put("en", "admin_reason");
        sampleReasonUser.put("en", "user_reason");
    }

    @Test
    public void testCAEPSessionRevokedEventPayload() {

        CAEPSessionRevokedEventPayload payload = new CAEPSessionRevokedEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity("admin")
                .reasonAdmin(sampleReasonAdmin)
                .reasonUser(sampleReasonUser)
                .build();

        assertNotNull(payload);
        assertEquals(payload.getEventTimeStamp(), eventTimeStamp);
        assertEquals(payload.getInitiatingEntity(), initiatingEntity);
        assertEquals(payload.getReasonAdmin(), sampleReasonAdmin);
        assertEquals(payload.getReasonUser(), sampleReasonUser);
    }

    @Test
    public void testCAEPSessionEstablishedAndPresentedPayload() {

        List<String> amr = new ArrayList<>();
        amr.add("password");
        amr.add("otp");
        String extId = "extId";
        String fpUa = "fpUa";
        List<String> ips = new ArrayList<>();
        ips.add("192.168.1.1");
        String acr = "acr";

        CAEPSessionEstablishedEventPayload payload =
                new CAEPSessionEstablishedEventPayload.Builder()
                        .eventTimeStamp(eventTimeStamp)
                        .initiatingEntity("admin")
                        .reasonAdmin(sampleReasonAdmin)
                        .reasonUser(sampleReasonUser)
                        .amr(amr)
                        .extId(extId)
                        .fpUa(fpUa)
                        .ips(ips)
                        .acr(acr)
                        .build();

        assertNotNull(payload);
        assertEquals(payload.getEventTimeStamp(), eventTimeStamp);
        assertEquals(payload.getInitiatingEntity(), initiatingEntity);
        assertEquals(payload.getReasonAdmin(), sampleReasonAdmin);
        assertEquals(payload.getReasonUser(), sampleReasonUser);
        assertEquals(payload.getAmr(), amr);
        assertEquals(payload.getExtId(), extId);
        assertEquals(payload.getFpUa(), fpUa);
        assertEquals(payload.getIps(), ips);
        assertEquals(payload.getAcr(), acr);
    }

    @Test
    public void testCAEPTokenClaimsChangePayload() {

        Map<String, String> claims = new HashMap<>();
        claims.put("claim1", "value1");
        claims.put("claim2", "value2");

        CAEPTokenClaimsChangeEventPayload payload =
                new CAEPTokenClaimsChangeEventPayload.Builder()
                        .eventTimeStamp(eventTimeStamp)
                        .initiatingEntity("admin")
                        .reasonAdmin(sampleReasonAdmin)
                        .reasonUser(sampleReasonUser)
                        .claims(claims)
                        .build();

        assertNotNull(payload);
        assertEquals(payload.getEventTimeStamp(), eventTimeStamp);
        assertEquals(payload.getInitiatingEntity(), initiatingEntity);
        assertEquals(payload.getReasonAdmin(), sampleReasonAdmin);
        assertEquals(payload.getReasonUser(), sampleReasonUser);
        assertEquals(payload.getClaims(), claims);
    }

    @Test
    public void testCAEPCredentialChangePayload() {

        String credentialType = "password";
        String changeType = "update";
        String friendlyName = "Password";
        String x509Issuer = "x509Issuer";
        String x509Serial = "x509Serial";
        String fidoAaguid = "fidoAaguid";

        CAEPCredentialChangeEventPayload payload = new CAEPCredentialChangeEventPayload.Builder()
                .eventTimeStamp(eventTimeStamp)
                .initiatingEntity("admin")
                .reasonAdmin(sampleReasonAdmin)
                .reasonUser(sampleReasonUser)
                .credentialType(credentialType)
                .changeType(CAEPCredentialChangeEventPayload.ChangeType.valueOf(changeType.toUpperCase()))
                .friendlyName(friendlyName)
                .x509Serial(x509Serial)
                .x509Issuer(x509Issuer)
                .fidoAaguid(fidoAaguid)
                .build();

        assertNotNull(payload);
        assertEquals(payload.getEventTimeStamp(), eventTimeStamp);
        assertEquals(payload.getInitiatingEntity(), initiatingEntity);
        assertEquals(payload.getReasonAdmin(), sampleReasonAdmin);
        assertEquals(payload.getReasonUser(), sampleReasonUser);
        assertEquals(payload.getCredentialType(), credentialType);
        assertEquals(payload.getChangeType().toString(), changeType);
        assertEquals(payload.getFriendlyName(), friendlyName);
        assertEquals(payload.getX509Issuer(), x509Issuer);
        assertEquals(payload.getX509Serial(), x509Serial);
        assertEquals(payload.getFidoAaguid(), fidoAaguid);
    }

    @Test
    public void testCAEPVerificationEventPayload() {

        String state = "state";

        CAEPVerificationEventPayload payload = new CAEPVerificationEventPayload.Builder()
                .state(state)
                .build();

        assertNotNull(payload);
        assertEquals(payload.getState(), state);
    }
}
