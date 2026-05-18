package org.cdpg.dx.auth.authorization.model;

import org.cdpg.dx.auth.authorization.handler.AuthorizationHandler;

/**
 * Authority tier matched by {@link AuthorizationHandler#forScopesWithContext(ScopeRule...)}.
 * Passed to the service layer via {@link AuthorizationContext} so the service can apply the
 * correct data boundary.
 */
public enum AuthLevel {

  /** Platform-wide authority — no data filter applied at the service. */
  PLATFORM,

  /** Organisation-scoped — service filters by the caller's {@code organisationId}. */
  ORG,

  /** Self-scoped — service filters by the caller's {@code sub}. */
  SELF
}