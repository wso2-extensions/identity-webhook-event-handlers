package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.identity.recovery.util.Utils;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.FIRST_NAME_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.LAST_NAME_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_ENDPOINT;

public class WSO2RegistrationEventPayloadBuilder implements RegistrationEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2RegistrationEventPayloadBuilder.class);

    @Override
    public EventPayload buildRegistrationSuccessEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration()
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        UserStore userStore = new UserStore(userStoreDomainName);

        String userName =
                String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.USER_NAME));

        String[] internalRoles;

        User newUser = new User();
        enrichUser(userStoreManager, userName, properties, newUser);
        addRoles(properties, newUser);

        try {
            internalRoles = userStoreManager.getRoleListOfUser(userName);
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error while retrieving roles for user: " + newUser.getId(), e);
        }

        List<String> registrationMethods = getRegistrationMethods(internalRoles);

        Organization organization = new Organization(tenantId, tenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        String initiatorType = "";
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
        }

        List<String> credentialEnrolled = new ArrayList<>();
        credentialEnrolled.add("PASSWORD");//TODO check totp and passkey flows later.

        return new WSO2RegistrationSuccessEventPayload.Builder()
                .initiatorType(initiatorType)
                .user(newUser)
                .organization(organization)
                .userStore(userStore)
                .registrationMethods(registrationMethods)
                .credentialsEnrolled(credentialEnrolled)
                .build();
    }

    private void enrichUser(UserStoreManager userStoreManager, String userName, Map<String, Object> properties,
                            User user)
            throws IdentityEventException {

        if (properties.containsKey(IdentityEventConstants.EventProperty.USER_CLAIMS)) {
            Map<String, String> claims = (Map<String, String>) properties.get(IdentityEventConstants.EventProperty
                    .USER_CLAIMS);

            String userId = claims.get(FrameworkConstants.USER_ID_CLAIM);
            user.setId(userId);
            user.setRef(
                    EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_ENDPOINT) + "/" + user.getId());

            List<UserClaim> userClaims = new ArrayList<>();
            String emailAddress = claims.get(FrameworkConstants.EMAIL_ADDRESS_CLAIM);
            String givenName = claims.get(FIRST_NAME_CLAIM_URI);
            String lastName = claims.get(LAST_NAME_CLAIM_URI);

            try {
                if (StringUtils.isEmpty(emailAddress)) {

                    emailAddress =
                            userStoreManager.getUserClaimValue(userName, FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                                    UserCoreConstants.DEFAULT_PROFILE);

                }
                if (StringUtils.isEmpty(givenName)) {

                    givenName = userStoreManager.getUserClaimValue(userName, FIRST_NAME_CLAIM_URI,
                            UserCoreConstants.DEFAULT_PROFILE);
                }

                if (StringUtils.isEmpty(lastName)) {

                    lastName = userStoreManager.getUserClaimValue(userName, LAST_NAME_CLAIM_URI,
                            UserCoreConstants.DEFAULT_PROFILE);

                }
            } catch (UserStoreException e) {
                throw new IdentityEventException(
                        "Error while extracting user claims for the user : " + user.getId(), e);
            }

            UserClaim emailAddressUserClaim = new UserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress);
            UserClaim givenNameUserClaim = new UserClaim(FIRST_NAME_CLAIM_URI, givenName);
            UserClaim lastNameUserClaim = new UserClaim(LAST_NAME_CLAIM_URI, lastName);

            userClaims.add(emailAddressUserClaim);
            userClaims.add(givenNameUserClaim);
            userClaims.add(lastNameUserClaim);
            user.setClaims(userClaims);
        } else {
            enrichUser(userStoreManager, userName, user);
        }
    }

    private List<String> getRegistrationMethods(String[] internalRoles) {

        if (internalRoles == null || internalRoles.length == 0) {
            return null;
        }
        List<String> roles = Arrays.asList(internalRoles);

        List<String> registrationMethods = new ArrayList<>();
        Claim emailVerifyTemporaryClaim = Utils.getEmailVerifyTemporaryClaim();

        if (roles.contains(IdentityRecoveryConstants.SELF_SIGNUP_ROLE)) {
            registrationMethods.add(UserOnboardedMethod.SELF_SIGNUP.name());
        } else if (emailVerifyTemporaryClaim != null &&
                IdentityRecoveryConstants.ASK_PASSWORD_CLAIM.equals(emailVerifyTemporaryClaim.getClaimUri())) {
            registrationMethods.add(UserOnboardedMethod.USER_INVITE.name());
        } else {
            registrationMethods.add(UserOnboardedMethod.ADMIN_INITIATED.name());
        }

        return registrationMethods;
    }

    private void addRoles(Map<String, Object> properties, User user) {

        if (!properties.containsKey(IdentityEventConstants.EventProperty.ROLE_LIST)) {
            return;
        }
        String[] roleList = (String[]) properties.get(IdentityEventConstants.EventProperty.ROLE_LIST);

        for (String role : roleList) {
            user.addRole(role);
        }
    }

    private static void enrichUser(UserStoreManager userStoreManager, String domainQualifiedUserName, User user)
            throws IdentityEventException {

        String userId;
        try {
            userId = userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.USER_ID_CLAIM,
                    UserCoreConstants.DEFAULT_PROFILE);
            user.setId(userId);

            user.setRef(
                    EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_ENDPOINT) + "/" + user.getId());

            List<UserClaim> userClaims = new ArrayList<>();

            String emailAddress =
                    userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                            UserCoreConstants.DEFAULT_PROFILE);
            String givenName = userStoreManager.getUserClaimValue(domainQualifiedUserName, FIRST_NAME_CLAIM_URI,
                    UserCoreConstants.DEFAULT_PROFILE);
            String lastName = userStoreManager.getUserClaimValue(domainQualifiedUserName, LAST_NAME_CLAIM_URI,
                    UserCoreConstants.DEFAULT_PROFILE);

            UserClaim emailAddressUserClaim = new UserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress);
            UserClaim givenNameUserClaim = new UserClaim(FIRST_NAME_CLAIM_URI, givenName);
            UserClaim lastNameUserClaim = new UserClaim(LAST_NAME_CLAIM_URI, lastName);

            userClaims.add(emailAddressUserClaim);
            userClaims.add(givenNameUserClaim);
            userClaims.add(lastNameUserClaim);

            user.setClaims(userClaims);

        } catch (UserStoreException e) {
            throw new IdentityEventException(
                    "Error while extracting user claims for the user : " + domainQualifiedUserName, e);
        }
    }

    @Override
    public EventSchema getEventSchemaType() {

        return EventSchema.WSO2;
    }

    /**
     * Enum which contains the different user onboarded flows.
     */
    public enum UserOnboardedMethod {

        ADMIN_INITIATED,
        USER_INVITE,
        SELF_SIGNUP
    }
}
