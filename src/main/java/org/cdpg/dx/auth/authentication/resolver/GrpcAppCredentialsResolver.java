package org.cdpg.dx.auth.authentication.resolver;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.client.AppIdVerificationClient;
import org.cdpg.dx.auth.appid.client.KeycloakServiceTokenProvider;
import org.cdpg.dx.auth.appid.v1.AppIdPrincipalProto;
import org.cdpg.dx.auth.appid.v1.VerifyAppIdResponse;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.cdpg.dx.common.model.DxUser;

/**
 * gRPC-backed {@link AppCredentialsResolver}. Calls the {@code VerifyAppId} RPC on
 * dx-controlplane and maps the response to a {@link DxUser}. Suitable for any external service
 * (dataplane, file-server, etc.) that cannot reach dx-controlplane's in-process EventBus.
 */
public final class GrpcAppCredentialsResolver implements AppCredentialsResolver {

  private static final Logger LOGGER = LogManager.getLogger(GrpcAppCredentialsResolver.class);

  private final AppIdVerificationClient client;
  private final KeycloakServiceTokenProvider tokenProvider;

  public GrpcAppCredentialsResolver(
      AppIdVerificationClient client, KeycloakServiceTokenProvider tokenProvider) {
    this.client = Objects.requireNonNull(client, "client");
    this.tokenProvider = Objects.requireNonNull(tokenProvider, "tokenProvider");
  }

  @Override
  public Future<DxUser> resolve(String appId, String secret) {
    return tokenProvider
        .getServiceToken()
        .compose(token -> client.verify(appId, secret, token))
        .compose(
            response -> {
              if (!response.getSuccess()) {
                LOGGER.debug("VerifyAppId rejected appId={}: {}", appId, response.getErrorCode());
                return Future.failedFuture(new DxUnauthorizedException("Invalid app credentials"));
              }
              return Future.succeededFuture(toDxUser(response));
            })
        .recover(
            err -> {
              if (err instanceof DxUnauthorizedException) return Future.failedFuture(err);
              String msg = err.getMessage();
              if (msg != null && msg.startsWith("Service misconfiguration")) {
                LOGGER.error(
                    "Cannot call VerifyAppId for appId={}: {} — fix config and restart", appId, msg);
              } else {
                LOGGER.error("gRPC VerifyAppId failed appId={}: {}", appId, msg);
              }
              return Future.failedFuture(err);
            });
  }

  private DxUser toDxUser(VerifyAppIdResponse response) {
    AppIdPrincipalProto proto = response.getPrincipal();
    // Proto uses underscore format (e.g. "data_access"); internal scope constants use hyphens.
    List<String> scopes =
        proto.getScopesList().stream()
            .map(s -> s.replace('_', '-'))
            .collect(Collectors.toList());
    LOGGER.info(
        "VerifyAppId success appId={} rawScopes={} normalizedScopes={}",
        proto.getAppId(),
        proto.getScopesList(),
        scopes);
    UUID sub = null;
    try {
      sub = UUID.fromString(proto.getUserId());
    } catch (IllegalArgumentException e) {
      LOGGER.warn("VerifyAppId returned non-UUID userId={}", proto.getUserId());
    }
    String orgId = proto.getOrganisationId().isBlank() ? null : proto.getOrganisationId();
    return new DxUser(
        List.of("consumer"), orgId, null, sub,
        false, false, null, null, null, null, null,
        null, null, null, null, null, null, null, null, null, null,
        new JsonArray(scopes), null, proto.getAppId());
  }
}
