package org.cdpg.dx.auth.authentication.resolver;

import io.vertx.core.Future;
import io.vertx.ext.auth.User;

public interface JwtResolver {
  Future<User> resolve(String token);
}
