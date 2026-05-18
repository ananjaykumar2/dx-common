package org.cdpg.dx.auth.authentication.resolver;

import io.vertx.core.Future;
import org.cdpg.dx.common.model.DxUser;

public interface AppCredentialsResolver {
  Future<DxUser> resolve(String appId, String secret);
}
