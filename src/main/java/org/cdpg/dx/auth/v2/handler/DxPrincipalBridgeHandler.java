package org.cdpg.dx.auth.v2.handler;

import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.web.RoutingContext;
import java.util.HashSet;
import java.util.Set;
import org.cdpg.dx.auth.appid.handler.AppIdAuthHandler;
import org.cdpg.dx.auth.v2.model.DxPrincipal;
import org.cdpg.dx.auth.v2.model.DxRole;
import org.cdpg.dx.auth.v2.model.Scopes;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Translates the v1 authentication result (ctx.user() set by CombinedAuthHandler) into a v2
 * DxPrincipal so that AuthorizationHandler.forScopes() can be used downstream without
 * running a second authentication pass.
 *
 * <p>Place this handler immediately after the OpenAPI security handler and before any
 * AuthorizationHandler-based scope check.
 */
public class DxPrincipalBridgeHandler implements Handler<RoutingContext> {

  @Override
  public void handle(RoutingContext ctx) {
    if (ctx.user() == null) {
      ctx.fail(new DxUnauthorizedException("No authenticated user"));
      return;
    }

    String appId = ctx.get(AppIdAuthHandler.APP_ID_KEY);
    DxPrincipal principal;

    if (appId != null) {
      // AppId-authenticated: scopes come from app_constraints via gRPC VerifyAppId
      JsonArray scopesArray = ctx.user().principal().getJsonArray("scopes");
      Set<String> directScopes = normalizeAppScopes(scopesArray);
      principal =
          DxPrincipal.builder()
              .authenticatedSub(ctx.user().subject())
              .appId(appId)
              .directScopes(directScopes)
              .build();
    } else {
      // JWT-authenticated: roles come from realm_access.roles in the token
      JsonArray rolesArray =
          ctx.user().principal().getJsonObject("realm_access").getJsonArray("roles");
      Set<DxRole> roles = mapJwtRoles(rolesArray);
      principal =
          DxPrincipal.builder()
              .authenticatedSub(ctx.user().subject())
              .authorizationRoles(roles)
              .build();
    }

    ctx.put(AuthorizationHandler.PRINCIPAL_KEY, principal);
    ctx.next();
  }

  private Set<String> normalizeAppScopes(JsonArray scopesArray) {
    if (scopesArray == null) {
      return Set.of();
    }
    Set<String> result = new HashSet<>();
    for (int i = 0; i < scopesArray.size(); i++) {
      String scope = scopesArray.getString(i);
      if ("*".equals(scope)) {
        return Scopes.ALL;
      }
      // DB stores "data_access"; v2 uses "data-access" — normalize underscore → hyphen
      result.add(scope.replace('_', '-'));
    }
    return result;
  }

  private Set<DxRole> mapJwtRoles(JsonArray rolesArray) {
    if (rolesArray == null) {
      return Set.of();
    }
    Set<DxRole> roles = new HashSet<>();
    for (int i = 0; i < rolesArray.size(); i++) {
      String roleName = rolesArray.getString(i);
      // v2 has no DELEGATE role; delegate users get CONSUMER scopes
      if ("delegate".equalsIgnoreCase(roleName)
          || "consumerDelegate".equalsIgnoreCase(roleName)) {
        roles.add(DxRole.CONSUMER);
      } else {
        DxRole.fromKeycloakName(roleName).ifPresent(roles::add);
      }
    }
    return roles;
  }
}
