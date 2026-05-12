package org.cdpg.dx.auth.v2.resolver;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import java.util.HashSet;
import java.util.Set;
import org.cdpg.dx.auth.v2.handler.AuthorizationHandler;
import org.cdpg.dx.auth.v2.model.DxPrincipal;
import org.cdpg.dx.auth.v2.model.DxRole;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Resolves a plain-user JWT (already validated by an upstream JWT auth handler) into a {@link
 * DxPrincipal}. Has no external dependencies — purely reads {@code ctx.user().principal()}.
 *
 * <p>Fails the context with {@link DxUnauthorizedException} if the token is missing the required
 * claim {@code sub}. The {@code organisation_id} claim is optional.
 */
public final class JwtPrincipalResolver {

  public void resolve(RoutingContext ctx) {
    User user = ctx.user();
    if (user == null) {
      ctx.fail(new DxUnauthorizedException("Missing JWT"));
      return;
    }
    JsonObject claims = user.principal();
    String sub = claims.getString("sub");
    String orgId = claims.getString("organisation_id");
    if (sub == null) {
      ctx.fail(new DxUnauthorizedException("JWT missing sub"));
      return;
    }

    Set<DxRole> roles = parseRoles(claims.getJsonObject("realm_access"));

    DxPrincipal principal =
        DxPrincipal.builder()
            .authenticatedSub(sub)
            .authenticatedOrgId(orgId)
            .authorizationRoles(roles)
            .auditRoles(roles)
            .build();

    ctx.put(AuthorizationHandler.PRINCIPAL_KEY, principal);
    ctx.next();
  }

  private static Set<DxRole> parseRoles(JsonObject realmAccess) {
    if (realmAccess == null) {
      return Set.of();
    }
    JsonArray arr = realmAccess.getJsonArray("roles");
    if (arr == null || arr.isEmpty()) {
      return Set.of();
    }
    Set<DxRole> roles = new HashSet<>();
    for (int i = 0; i < arr.size(); i++) {
      Object raw = arr.getValue(i);
      if (raw == null) continue;
      DxRole.fromKeycloakName(raw.toString()).ifPresent(roles::add);
    }
    return roles;
  }
}
