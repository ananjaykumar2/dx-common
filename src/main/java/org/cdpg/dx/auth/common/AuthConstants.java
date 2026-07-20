package org.cdpg.dx.auth.common;

public final class AuthConstants {

  // --- Error: General ---
  public static final String MISSING_CREDENTIALS   = "Missing credentials";
  public static final String AMBIGUOUS_CREDENTIALS = "Ambiguous credentials: send either JWT or app credentials, not both";
  public static final String UNAUTHORIZED          = "Unauthorized: %s";

  // --- Error: Bearer / JWT ---
  public static final String MISSING_BEARER_TOKEN  = "Missing Bearer token";
  public static final String INVALID_TOKEN_FORMAT  = "Invalid token format";
  public static final String MALFORMED_JWT         = "Malformed JWT";
  public static final String INVALID_SUB_UUID      = "Invalid or missing 'sub' UUID in token";
  public static final String INVALID_TOKEN         = "Token is invalid";

  // --- Error: Basic / AppId ---
  public static final String INVALID_BASIC_CREDENTIALS = "Invalid Basic credentials";
  public static final String MISSING_BASIC_AUTH        = "Missing or invalid Authorization header (expected Basic auth)";
  public static final String INVALID_BASIC_FORMAT      = "Invalid Basic auth format (expected base64(appId:appSecret))";
  public static final String INVALID_BASE64            = "Invalid Base64 in Authorization header";
  public static final String BLANK_APP_CREDENTIALS     = "AppId or AppSecret must not be blank";
  public static final String INVALID_APP_CREDENTIALS   = "Invalid AppId credentials";
  public static final String AUTH_SERVICE_UNAVAILABLE  = "Authentication service unavailable";

  // --- Error: Authorization ---
  public static final String INSUFFICIENT_SCOPE    = "Insufficient scope";
  public static final String WRONG_ROLE            = "User does not hold the required role";
  public static final String MISSING_ORG_CONTEXT   = "User holds an organisation-scoped role but the token carries no organisation context";
  public static final String NO_AUTHENTICATED_USER = "No authenticated user";
  public static final String KYC_NOT_VERIFIED      = "KYC verification required";

  // --- Internal principal keys ---
  public static final String DELEGATOR_HEADER_KEY = "_delegatorHeader";
  public static final String HEADER_DID           = "did";

  // --- AppId issuer ---
  public static final String ISSUER_DEFAULT = "dx-controlplane";

  // --- JWKS / JWT config keys ---
  public static final String JWT_IGNORE_EXPIRY      = "jwtIgnoreExpiry";
  public static final String JWT_LEEWAY             = "jwtLeeway";
  public static final String JWKS_REFRESH_INTERVAL  = "jwksRefreshIntervalMs";
  public static final String JWKS_TYPE              = "type";
  public static final String JWKS_URL               = "jwksUrl";

  // --- Routing context keys ---
  public static final String AUTH_FAILED = "auth_failed";
  public static final String AUTH_ERROR  = "auth_error";

  private AuthConstants() {}
}
