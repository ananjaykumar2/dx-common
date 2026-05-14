package org.cdpg.dx.auth.authentication.lookup;

import io.vertx.core.Future;
import java.util.Optional;
import org.cdpg.dx.auth.model.DelegationRecord;

/**
 * SPI for finding an active delegation from delegator → delegatee. Implementations may hit a local
 * service (controlplane) or a remote gRPC endpoint (dataplane, acl-apd).
 *
 * <p>An {@code Optional.empty()} success means "no active delegation" and should translate into
 * 403 at the HTTP layer. The {@code Future} is failed only for transport/infrastructure errors.
 */
public interface DelegationLookup {

  Future<Optional<DelegationRecord>> findActive(String delegatorSub, String delegateeSub);
}