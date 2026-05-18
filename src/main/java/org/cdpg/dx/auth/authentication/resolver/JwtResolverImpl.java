package org.cdpg.dx.auth.authentication.resolver;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.authentication.TokenCredentials;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.cdpg.dx.auth.authentication.client.JwksResolver;
import org.cdpg.dx.auth.authentication.util.JwtTokenUtil;
import org.cdpg.dx.auth.authorization.registry.SystemRoleScopeMap;
import org.cdpg.dx.auth.common.AuthConstants;
import org.cdpg.dx.auth.model.DxRole;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.cdpg.dx.keycloak.config.KeycloakConstants;

public final class JwtResolverImpl implements JwtResolver {

  private final JwksResolver jwksResolver;

  public JwtResolverImpl(JwksResolver jwksResolver) {
    this.jwksResolver = Objects.requireNonNull(jwksResolver, "jwksResolver");
  }

  @Override
  public Future<User> resolve(String token) {
    String issuer;
    String kid;
    try {
      issuer = JwtTokenUtil.extractIssuer(token);
      kid = JwtTokenUtil.extractKid(token);
    } catch (Exception e) {
      return Future.failedFuture(new DxUnauthorizedException("Invalid token format"));
    }

    return jwksResolver
        .resolve(issuer, kid)
        .compose(jwtAuth -> jwtAuth.authenticate(new TokenCredentials(token)))
        .map(JwtResolverImpl::enrichWithScopes)
        .recover(err -> Future.failedFuture(
            new DxUnauthorizedException(AuthConstants.UNAUTHORIZED.formatted(err.getMessage()))));
  }

  private static User enrichWithScopes(User jwtUser) {
    JsonObject principal = jwtUser.principal().copy();
    JsonArray roles = principal
        .getJsonObject(KeycloakConstants.CLAIM_REALM_ACCESS, new JsonObject())
        .getJsonArray(KeycloakConstants.CLAIM_ROLES, new JsonArray());

    Set<String> scopeSet = new HashSet<>();
    for (Object r : roles) {
      DxRole.fromString(r.toString())
          .ifPresent(role -> scopeSet.addAll(SystemRoleScopeMap.getScopes(role)));
    }

    JsonArray scopesArr = new JsonArray();
    scopeSet.forEach(scopesArr::add);
    principal.put(KeycloakConstants.CLAIM_SCOPES, scopesArr);

    return User.create(principal);
  }
}