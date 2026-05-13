package org.cdpg.dx.auth.v2.registry;

import java.util.Set;
import org.cdpg.dx.auth.v2.model.DxPrincipal;

/**
 * Resolves a principal's effective scope set.
 *
 * @deprecated Scope resolution now happens at authentication time inside the auth handlers
 *     (AuthenticationHandlerV2, DelegationResolver, AppCredentialsResolver) using
 *     {@link org.cdpg.dx.auth.v2.registry.SystemRoleScopeMap} directly. The resolved scopes are
 *     stored under the {@code "scopes"} key in the Vert.x User principal and read by the v2
 *     AuthorizationHandler via {@code ctx.user()}.
 */
@Deprecated
public interface RoleScopeRegistry {

  /** @deprecated See class-level deprecation note. */
  @Deprecated
  Set<String> resolveEffectiveScopes(DxPrincipal principal);
}