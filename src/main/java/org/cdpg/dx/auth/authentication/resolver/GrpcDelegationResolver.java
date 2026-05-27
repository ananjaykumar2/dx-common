package org.cdpg.dx.auth.authentication.resolver;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.client.AppIdVerificationClient;
import org.cdpg.dx.auth.appid.client.KeycloakServiceTokenProvider;
import org.cdpg.dx.auth.appid.v1.ResolveDelegationResponse;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.model.DxUser;

/**
 * gRPC-backed {@link DelegationResolver}. Calls the {@code ResolveDelegation} RPC on
 * dx-controlplane and maps the response to a {@link DxUser} representing the delegator.
 * Suitable for any external service (dataplane, file-server, etc.) that cannot reach
 * dx-controlplane's in-process EventBus.
 */
public final class GrpcDelegationResolver implements DelegationResolver {

  private static final Logger LOGGER = LogManager.getLogger(GrpcDelegationResolver.class);
  private static final int CACHE_MAX_SIZE = 1000;
  private static final int CACHE_TTL_MINUTES = 2;

  private final AppIdVerificationClient client;
  private final KeycloakServiceTokenProvider tokenProvider;
  private final Cache<String, DxUser> delegationCache;

  public GrpcDelegationResolver(
      AppIdVerificationClient client, KeycloakServiceTokenProvider tokenProvider) {
    this.client = Objects.requireNonNull(client, "client");
    this.tokenProvider = Objects.requireNonNull(tokenProvider, "tokenProvider");
    this.delegationCache = CacheBuilder.newBuilder()
        .maximumSize(CACHE_MAX_SIZE)
        .expireAfterWrite(CACHE_TTL_MINUTES, TimeUnit.MINUTES)
        .build();
  }

  @Override
  public Future<DxUser> resolve(String delegatorSub, String delegateeSub) {
    String cacheKey = delegatorSub + ":" + delegateeSub;
    DxUser cached = delegationCache.getIfPresent(cacheKey);
    if (cached != null) {
      LOGGER.debug("Delegation cache hit delegatorSub={} delegateeSub={}", delegatorSub, delegateeSub);
      return Future.succeededFuture(cached);
    }

    return tokenProvider
        .getServiceToken()
        .compose(token -> client.resolveDelegation(delegatorSub, delegateeSub, token))
        .compose(
            response -> {
              if (!response.getSuccess()) {
                LOGGER.debug(
                    "ResolveDelegation rejected delegatorSub={} delegateeSub={}: {}",
                    delegatorSub, delegateeSub, response.getErrorCode());
                return Future.failedFuture(new DxForbiddenException("No active delegation"));
              }
              DxUser user = toDxUser(response);
              delegationCache.put(cacheKey, user);
              return Future.succeededFuture(user);
            })
        .recover(
            err -> {
              if (err instanceof DxForbiddenException) return Future.failedFuture(err);
              String msg = err.getMessage();
              if (msg != null && msg.startsWith("Service misconfiguration")) {
                LOGGER.error(
                    "Cannot call ResolveDelegation for delegatorSub={}: {} — fix config and restart",
                    delegatorSub, msg);
              } else {
                LOGGER.error("gRPC ResolveDelegation failed delegatorSub={}: {}", delegatorSub, msg);
              }
              return Future.failedFuture(err);
            });
  }

  private DxUser toDxUser(ResolveDelegationResponse r) {
    UUID sub = null;
    try {
      if (r.getSub() != null && !r.getSub().isBlank()) {
        sub = UUID.fromString(r.getSub());
      }
    } catch (IllegalArgumentException e) {
      LOGGER.warn("ResolveDelegation returned non-UUID sub={}", r.getSub());
    }

    List<String> roles = r.getRolesList().isEmpty() ? null : r.getRolesList();
    JsonArray scopes = r.getScopesList().isEmpty() ? null : new JsonArray(r.getScopesList());

    String orgId = r.getOrganisationId().isBlank() ? null : r.getOrganisationId();
    String orgName = r.getOrganisationName().isBlank() ? null : r.getOrganisationName();
    String name = r.getName().isBlank() ? null : r.getName();
    String preferredUsername = r.getPreferredUsername().isBlank() ? null : r.getPreferredUsername();
    String givenName = r.getGivenName().isBlank() ? null : r.getGivenName();
    String familyName = r.getFamilyName().isBlank() ? null : r.getFamilyName();
    String email = r.getEmail().isBlank() ? null : r.getEmail();
    String delegateeId = r.getDelegateeSub().isBlank() ? null : r.getDelegateeSub();

    return new DxUser(
        roles,
        orgId,
        orgName,
        sub,
        r.getEmailVerified(),
        r.getKycVerified(),
        name,
        preferredUsername,
        givenName,
        familyName,
        email,
        null,  // pendingRoles
        null,  // organisation
        null,  // createdAt
        null,  // kycData
        null,  // twitter_account
        null,  // linkedin_account
        null,  // github_account
        r.getAccountEnabled(),
        null,  // did
        null,  // aud
        scopes,
        delegateeId,
        null); // appId
  }
}
