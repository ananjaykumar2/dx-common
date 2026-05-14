package org.cdpg.dx.auth.model;

import org.cdpg.dx.auth.authentication.lookup.AppCredentialLookup;

import java.util.List;

/**
 * Result of a successful app-credential verification, produced by {@link
 * AppCredentialLookup} implementations.
 *
 * <p>Shape mirrors the gRPC {@code VerifyAppIdResponse.principal} so both local (in-process) and
 * gRPC-backed lookups produce the same DTO.
 *
 * @param appId          app identifier (safe to log)
 * @param ownerSub       user sub of the app owner
 * @param ownerOrgId     organisation of the owner at the time of lookup (may be null if the lookup
 *                       doesn't supply it — the resolver will fetch it via {@link UserLookup})
 * @param appScopes      scopes bound to this app, as stored at create/update time (pre-cap)
 * @param expiresAtEpoch seconds since epoch; {@code 0} means no expiry
 * @param active         {@code true} iff not revoked and not expired
 */
public record AppPrincipal(
    String appId,
    String ownerSub,
    String ownerOrgId,
    List<String> appScopes,
    long expiresAtEpoch,
    boolean active) {}