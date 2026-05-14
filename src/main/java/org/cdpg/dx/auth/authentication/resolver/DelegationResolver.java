package org.cdpg.dx.auth.authentication.resolver;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import org.cdpg.dx.auth.authentication.lookup.DelegationLookup;
import org.cdpg.dx.auth.authentication.lookup.UserLookup;
import org.cdpg.dx.auth.model.DelegationRecord;
import org.cdpg.dx.auth.model.DxRole;
import org.cdpg.dx.auth.model.UserSnapshot;
import org.cdpg.dx.auth.authorization.registry.SystemRoleScopeMap;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;

/**
 * Resolves a JWT + {@code delegatorId} header into a Vert.x {@link User} acting <em>as</em> the
 * delegator. The JWT must already be validated by an upstream auth handler.
 *
 * <p>Sets {@code ctx.user()} with a principal JSON containing:
 * <ul>
 *   <li>{@code sub} — delegator's sub (effective identity)
 *   <li>{@code organisation_id} — delegator's org
 *   <li>{@code realm_access.roles} — delegator's current roles
 *   <li>{@code delegation_scope} — capped effective scopes
 *   <li>{@code delegatee_sub} — JWT sub (for audit)
 *   <li>{@code delegatee_org_id} — JWT org (for audit, if present)
 * </ul>
 */
public final class DelegationResolver {

  private final DelegationLookup delegationLookup;
  private final UserLookup userLookup;

  public DelegationResolver(DelegationLookup delegationLookup, UserLookup userLookup) {
    this.delegationLookup = Objects.requireNonNull(delegationLookup, "delegationLookup");
    this.userLookup = Objects.requireNonNull(userLookup, "userLookup");
  }

  public void resolve(RoutingContext ctx) {
    User jwtUser = ctx.user();
    if (jwtUser == null) {
      ctx.fail(new DxUnauthorizedException("Missing JWT"));
      return;
    }
    JsonObject claims = jwtUser.principal();
    String delegateeSub = claims.getString("sub");
    String delegateeOrgId = claims.getString("organisation_id");
    if (delegateeSub == null) {
      ctx.fail(new DxUnauthorizedException("JWT missing sub"));
      return;
    }

    String delegatorSub = ctx.request().getHeader("did");
    if (delegatorSub == null || delegatorSub.isBlank()) {
      ctx.fail(new DxUnauthorizedException("Missing did in header"));
      return;
    }

    delegationLookup
        .findActive(delegatorSub, delegateeSub)
        .onFailure(err -> ctx.fail(new DxUnauthorizedException("Delegation lookup failed")))
        .onSuccess(
            maybeDelegation -> {
              if (maybeDelegation.isEmpty() || !maybeDelegation.get().active()) {
                ctx.fail(new DxForbiddenException("No active delegation from " + delegatorSub));
                return;
              }
              DelegationRecord delegation = maybeDelegation.get();
              if (isExpired(delegation)) {
                ctx.fail(new DxForbiddenException("Delegation has expired"));
                return;
              }

              userLookup
                  .findBySub(delegatorSub)
                  .onFailure(err -> ctx.fail(new DxUnauthorizedException("User lookup failed")))
                  .onSuccess(
                      maybeDelegator -> {
                        if (maybeDelegator.isEmpty() || maybeDelegator.get().disabled()) {
                          ctx.fail(new DxForbiddenException("Delegator is no longer active"));
                          return;
                        }
                        UserSnapshot delegator = maybeDelegator.get();
                        User user = buildUser(delegateeSub, delegateeOrgId, delegator, delegation);
                        ctx.setUser(user);
                        ctx.next();
                      });
            });
  }

  private User buildUser(
      String delegateeSub,
      String delegateeOrgId,
      UserSnapshot delegator,
      DelegationRecord delegation) {

    Set<String> delegatorCurrentScopes = flatten(delegator.roles());
    Set<String> capped;
    if (delegation.fullDelegation()) {
      capped = delegatorCurrentScopes;
    } else {
      capped = new HashSet<>(delegation.scopes());
      capped.retainAll(delegatorCurrentScopes);
    }

    JsonArray rolesArr = new JsonArray();
    for (DxRole r : delegator.roles()) rolesArr.add(r.value());

    JsonArray scopesArr = new JsonArray();
    for (String s : capped) scopesArr.add(s);

    JsonObject principal =
        new JsonObject()
            .put("sub", delegator.sub())
            .put("organisation_id", delegator.organisationId())
            .put("realm_access", new JsonObject().put("roles", rolesArr))
            .put("scopes", scopesArr)
            .put("delegatee_sub", delegateeSub);
    if (delegateeOrgId != null) {
      principal.put("delegatee_org_id", delegateeOrgId);
    }

    return User.create(principal);
  }

  private static boolean isExpired(DelegationRecord d) {
    long exp = d.expiresAtEpoch();
    return exp != 0 && exp < Instant.now().getEpochSecond();
  }

  private static Set<String> flatten(Set<DxRole> roles) {
    Set<String> out = new HashSet<>();
    for (DxRole r : roles) out.addAll(SystemRoleScopeMap.getScopes(r));
    return out;
  }
}