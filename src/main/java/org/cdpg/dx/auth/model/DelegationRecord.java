package org.cdpg.dx.auth.model;

import org.cdpg.dx.auth.authentication.lookup.DelegationLookup;

import java.util.Set;

/**
 * Result of a delegation lookup, produced by {@link
 * DelegationLookup} implementations.
 *
 * @param delegatorSub    the user whose authority is being borrowed
 * @param delegateeSub    the user who may borrow that authority
 * @param scopes          scopes granted by the delegation; empty when {@code fullDelegation} is
 *                        {@code true} (in which case the resolver uses the delegator's current
 *                        flattened scopes)
 * @param fullDelegation  if {@code true}, the delegatee receives all of the delegator's current
 *                        scopes at request time
 * @param active          {@code true} iff not revoked and not expired
 * @param expiresAtEpoch  seconds since epoch; {@code 0} means no expiry
 */
public record DelegationRecord(
    String delegatorSub,
    String delegateeSub,
    Set<String> scopes,
    boolean fullDelegation,
    boolean active,
    long expiresAtEpoch) {

  public DelegationRecord {
    scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
  }
}