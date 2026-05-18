package org.cdpg.dx.auth.authentication.resolver;

import io.vertx.core.Future;
import org.cdpg.dx.common.model.DxUser;

public interface DelegationResolver {
  Future<DxUser> resolve(String delegatorSub, String delegateeSub);
}
