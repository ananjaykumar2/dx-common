package org.cdpg.dx.keycloak.config;

/**
 * Shared Keycloak attribute key constants used across DX microservices.
 */
public class KeycloakConstants {

  // Keycloak user attribute keys
  public static final String ORGANISATION_ID   = "organisation_id";
  public static final String ORGANISATION_NAME = "organisation_name";
  public static final String DID               = "did";
  public static final String AUD               = "aud";
  public static final String KYC_VERIFIED      = "kyc_verified";
  public static final String AADHAAR_KYC_DATA  = "aadhaar_kyc_data";
  public static final String SCOPES            = "delegation_scope";
  public static final String DELEGATION_ROLES  = "delegation_access_roles";
  public static final String USER_SCOPE        = "scope";

  // Keycloak role names
  public static final String ORG_ADMIN_ROLE  = "org_admin";
  public static final String PF_ADMIN_ROLE   = "cos_admin";
  public static final String PROVIDER_ROLE   = "provider";
  public static final String DELEGATE_ROLE   = "delegate";

  // JWT principal claim keys
  public static final String CLAIM_SUB            = "sub";
  public static final String CLAIM_REALM_ACCESS   = "realm_access";
  public static final String CLAIM_ROLES          = "roles";
  public static final String CLAIM_SCOPES         = "scopes";
  public static final String CLAIM_EMAIL_VERIFIED = "email_verified";
  public static final String CLAIM_DELEGATEE_SUB  = "delegatee_sub";
  public static final String CLAIM_APP_ID         = "app_id";

  // Standard OIDC claim keys
  public static final String CLAIM_ISS               = "iss";
  public static final String CLAIM_KID               = "kid";
  public static final String CLAIM_NAME               = "name";
  public static final String CLAIM_EMAIL              = "email";
  public static final String CLAIM_GIVEN_NAME         = "given_name";
  public static final String CLAIM_FAMILY_NAME        = "family_name";
  public static final String CLAIM_PREFERRED_USERNAME = "preferred_username";

  // JWKS response keys
  public static final String JWKS_KEYS = "keys";

  private KeycloakConstants() {}
}
