package org.cdpg.dx.auth.authentication.lookup;

import io.vertx.core.Future;
import java.util.Optional;
import org.cdpg.dx.auth.model.AppPrincipal;

/**
 * SPI for verifying app credentials. Implementations may hit a local service (controlplane) or a
 * remote gRPC endpoint (dataplane, acl-apd) — resolvers don't know or care.
 *
 * <p>An {@code Optional.empty()} success indicates a legitimate "not found / invalid credentials"
 * result that the resolver should translate into a 401. The {@code Future} is failed only for
 * transport/infrastructure errors (5xx territory).
 */
public interface AppCredentialLookup {

  Future<Optional<AppPrincipal>> verify(String appId, String appSecret);
}