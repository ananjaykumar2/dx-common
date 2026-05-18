package org.cdpg.dx.common.util;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auditing.model.AuditLog;
import org.cdpg.dx.auth.authentication.exception.AuthenticationException;
import org.cdpg.dx.auth.common.AuthConstants;
import org.cdpg.dx.common.exception.DxBadRequestException;
import org.cdpg.dx.common.model.DxUser;
import org.cdpg.dx.keycloak.config.KeycloakConstants;

/**
 * Common routing context helper with shared methods for getting/setting context data. Base projects
 * can create project-specific helpers (e.g. CpRoutingContextHelper, RsRoutingContextHelper) for
 * methods that depend on project-specific types.
 */
public class RoutingContextHelper {
  private static final Logger LOGGER = LogManager.getLogger(RoutingContextHelper.class);

  private static final String AUDITING_LOG = "auditingLog";
  private static final String RESPONSE_SIZE = "responseSize";
  private static final String ID = "id";
  private static final String ITEM_META_DATA = "itemMetaData";
  private static final String IID = "iid";
  private static final String DX_USER = "dxUser";
  private static final String USER_KEY = "user";
  private static final String HEADER_AUTHORIZATION = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";
  private static final String PROVIDER_ID = "providerId";
  private static final String POLICY_EXPIRY_AT = "policyExpiryAt";
  private static final String APPLICABLE_FILTER = "applicableFilter";
  private static final String ACCESS_POLICY = "accessPolicy";
  private static final String ALLOWED_ATTRIBUTES = "allowedattributes";
  private static final String OWNER_USER_ID = "ownerUserId";
  private static final String DID = "did";
  private static final String POLICY_ID = "policyId";
  private static final String API_ENDPOINT = "apiEndpoint";

  private RoutingContextHelper() {}

  // --- Auditing ---

  public static Optional<List<AuditLog>> getAuditingLog(RoutingContext routingContext) {
    return Optional.ofNullable(routingContext.get(AUDITING_LOG));
  }

  public static void setAuditingLog(RoutingContext routingContext, AuditLog auditingLog) {
    List<AuditLog> logs = getAuditingLog(routingContext).orElseGet(ArrayList::new);
    logs.add(auditingLog);
    routingContext.put(AUDITING_LOG, logs);
  }

  // --- User (Vert.x auth User) ---

  public static void setUser(RoutingContext routingContext, User user) {
    routingContext.put(USER_KEY, user);
  }

  public static User getUser(RoutingContext routingContext) {
    return routingContext.get(USER_KEY);
  }

  // --- DxUser ---

  public static void setDxUser(RoutingContext routingContext, DxUser dxUser) {
    routingContext.put(DX_USER, dxUser);
  }

  public static DxUser getDxUser(RoutingContext routingContext) {
    return routingContext.get(DX_USER);
  }

  // --- Token extraction ---

  public static Optional<String> getToken(RoutingContext routingContext) {
    return Optional.ofNullable(routingContext.request().getHeader(HEADER_AUTHORIZATION))
        .filter(authHeader -> authHeader.startsWith(BEARER_PREFIX))
        .map(authHeader -> authHeader.substring(BEARER_PREFIX.length()).trim());
  }

  public static String getTokenOrThrow(RoutingContext routingContext) {
    return getToken(routingContext)
        .orElseThrow(() -> new AuthenticationException(AuthConstants.INVALID_TOKEN));
  }

  // --- Auth info ---

  public static JsonObject getAuthInfo(RoutingContext routingContext) {
    return new JsonObject()
        .put(API_ENDPOINT, getRequestPath(routingContext))
        .put("token", getTokenOrThrow(routingContext))
        .put("method", getMethod(routingContext));
  }

  // --- Request metadata ---

  public static String getRequestPath(RoutingContext routingContext) {
    return routingContext.request().path();
  }

  public static String getMethod(RoutingContext routingContext) {
    return routingContext.request().method().toString();
  }

  public static void setId(RoutingContext event, String id) {
    event.put(ID, id);
  }

  public static String getId(RoutingContext event) {
    return event.get(ID);
  }

  public static void setResponseSize(RoutingContext event, long responseSize) {
    event.data().put(RESPONSE_SIZE, responseSize);
  }

  public static Long getResponseSize(RoutingContext event) {
    return (Long) event.data().get(RESPONSE_SIZE);
  }

  public static void setItemMetaData(RoutingContext context, JsonObject result) {
    context.put(ITEM_META_DATA, result);
  }

  public static JsonObject getItemMetaData(RoutingContext event) {
    return event.get(ITEM_META_DATA);
  }

  public static void setIid(RoutingContext context, String iid) {
    context.put(IID, iid);
  }

  public static String getIid(RoutingContext event) {
    return event.get(IID);
  }

  // --- Provider / Policy ---

  public static void setProviderId(RoutingContext routingContext, String providerId) {
    routingContext.put(PROVIDER_ID, providerId);
  }

  public static String getProviderId(RoutingContext routingContext) {
    return routingContext.get(PROVIDER_ID);
  }

  public static void setPolicyExpiryAt(RoutingContext routingContext, String policyExpiryAt) {
    routingContext.put(POLICY_EXPIRY_AT, policyExpiryAt);
  }

  public static String getPolicyExpiryAt(RoutingContext routingContext) {
    return routingContext.get(POLICY_EXPIRY_AT);
  }

  public static void setPolicyId(RoutingContext context, String policyId) {
    context.put(POLICY_ID, policyId);
  }

  public static String getPolicyId(RoutingContext event) {
    return event.get(POLICY_ID);
  }

  // --- Access control ---

  public static void setApplicableFilter(RoutingContext event, JsonArray filter) {
    event.put(APPLICABLE_FILTER, filter);
  }

  public static JsonArray getApplicableFilter(RoutingContext event) {
    return event.get(APPLICABLE_FILTER);
  }

  public static void setAccessPolicy(RoutingContext context, String accessPolicy) {
    context.put(ACCESS_POLICY, accessPolicy);
  }

  public static String getAccessPolicy(RoutingContext event) {
    return event.get(ACCESS_POLICY);
  }

  public static void setAllowedAttributes(RoutingContext context, JsonArray allowedAttributes) {
    context.put(ALLOWED_ATTRIBUTES, allowedAttributes);
  }

  public static JsonArray getAllowedAttributes(RoutingContext event) {
    return event.get(ALLOWED_ATTRIBUTES);
  }

  public static void setOwnerUserId(RoutingContext context, String ownerUserId) {
    context.put(OWNER_USER_ID, ownerUserId);
  }

  public static String getOwnerUserId(RoutingContext event) {
    return event.get(OWNER_USER_ID);
  }

  public static void setDid(RoutingContext context, String did) {
    context.put(DID, did);
  }

  public static String getDid(RoutingContext event) {
    return event.get(DID);
  }

  // --- Endpoint ---

  public static void setEndPoint(RoutingContext event, String normalisedPath) {
    event.put(API_ENDPOINT, normalisedPath);
  }

  public static String getEndPoint(RoutingContext event) {
    return event.get(API_ENDPOINT);
  }

  // --- Principal to DxUser ---

  public static DxUser fromPrincipal(RoutingContext ctx) {
    JsonObject principal = ctx.user().principal();

    List<String> roles =
        principal
            .getJsonObject(KeycloakConstants.CLAIM_REALM_ACCESS, new JsonObject())
            .getJsonArray(KeycloakConstants.CLAIM_ROLES, new JsonArray())
            .getList();

    UUID userId;
    try {
      userId = UUID.fromString(principal.getString(KeycloakConstants.CLAIM_SUB));
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new DxBadRequestException(AuthConstants.INVALID_SUB_UUID);
    }

    JsonArray scopes     = principal.getJsonArray(KeycloakConstants.CLAIM_SCOPES, new JsonArray());
    String delegateeId   = principal.getString(KeycloakConstants.CLAIM_DELEGATEE_SUB, null);
    String appId         = principal.getString(KeycloakConstants.CLAIM_APP_ID, null);

    return new DxUser(
        roles,
        principal.getString(KeycloakConstants.ORGANISATION_ID, null),
        principal.getString(KeycloakConstants.ORGANISATION_NAME, null),
        userId,
        principal.getBoolean(KeycloakConstants.CLAIM_EMAIL_VERIFIED, false),
        principal.getBoolean(KeycloakConstants.KYC_VERIFIED, false),
        principal.getString(KeycloakConstants.CLAIM_NAME),
        principal.getString(KeycloakConstants.CLAIM_PREFERRED_USERNAME),
        principal.getString(KeycloakConstants.CLAIM_GIVEN_NAME),
        principal.getString(KeycloakConstants.CLAIM_FAMILY_NAME),
        principal.getString(KeycloakConstants.CLAIM_EMAIL),
        new ArrayList<>(),
        new JsonObject(),
        null,
        new JsonObject(),
        "",
        "",
        "",
        null,
        principal.getString(KeycloakConstants.DID, null),
        principal.getString(KeycloakConstants.AUD, null),
        scopes,
        delegateeId,
        appId);
  }
}
