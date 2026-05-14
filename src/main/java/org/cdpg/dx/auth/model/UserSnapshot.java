package org.cdpg.dx.auth.model;

import org.cdpg.dx.auth.authentication.lookup.UserLookup;

import java.util.Set;

/**
 * Snapshot of a user's current authorization-relevant state, produced by {@link
 * UserLookup} implementations. Used by the delegation and app resolvers
 * to cap scopes against the delegator's / owner's current role set.
 *
 * @param sub             user sub
 * @param organisationId  user's current organisation
 * @param roles           user's current system roles
 * @param disabled        {@code true} if the user is disabled or otherwise no longer active
 */
public record UserSnapshot(
        String sub, String organisationId, Set<DxRole> roles, boolean disabled) {

  public UserSnapshot {
    roles = roles == null ? Set.of() : Set.copyOf(roles);
  }
}