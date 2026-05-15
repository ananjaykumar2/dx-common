package org.cdpg.dx.auth.authentication.lookup;

import io.vertx.core.Future;
import java.util.Optional;
import org.cdpg.dx.common.model.DxUser;

/**
 * SPI for loading a user's current state. Used by the delegation and app resolvers to cap scopes
 * against the delegator's / owner's current role set.
 *
 * <p>An {@code Optional.empty()} success means "no such user" and typically translates into 403.
 * The {@code Future} is failed only for transport/infrastructure errors.
 */
public interface UserLookup {

  Future<Optional<DxUser>> findBySub(String sub);
}