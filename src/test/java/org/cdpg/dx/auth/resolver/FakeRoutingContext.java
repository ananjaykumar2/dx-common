package org.cdpg.dx.auth.resolver;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import java.util.HashMap;
import java.util.Map;

/**
 * Minimal Vert.x {@link RoutingContext} fake for resolver tests. Records put/get, next(), and
 * fail(Throwable); routes header lookups through a map.
 */
final class FakeRoutingContext {

  final RoutingContext ctx = mock(RoutingContext.class);
  private final HttpServerRequest req = mock(HttpServerRequest.class);
  final Map<String, Object> data = new HashMap<>();
  final Map<String, String> headers = new HashMap<>();
  Throwable failedWith;
  boolean nextCalled;
  User currentUser;

  FakeRoutingContext() {
    when(ctx.request()).thenReturn(req);
    when(req.getHeader(anyString())).thenAnswer(inv -> headers.get(inv.<String>getArgument(0)));
    when(ctx.get(anyString())).thenAnswer(inv -> data.get(inv.<String>getArgument(0)));
    when(ctx.put(anyString(), any()))
        .thenAnswer(
            inv -> {
              data.put(inv.getArgument(0), inv.getArgument(1));
              return ctx;
            });
    when(ctx.user()).thenAnswer(inv -> currentUser);
    doAnswer(
            inv -> {
              currentUser = inv.getArgument(0);
              return null;
            })
        .when(ctx)
        .setUser(any(User.class));
    doAnswer(
            inv -> {
              nextCalled = true;
              return null;
            })
        .when(ctx)
        .next();
    doAnswer(
            inv -> {
              failedWith = inv.getArgument(0);
              return null;
            })
        .when(ctx)
        .fail(any(Throwable.class));
  }

  FakeRoutingContext header(String name, String value) {
    headers.put(name, value);
    return this;
  }

  FakeRoutingContext userWithClaims(JsonObject claims) {
    currentUser = User.create(claims);
    return this;
  }

  FakeRoutingContext noUser() {
    when(ctx.user()).thenReturn(null);
    return this;
  }
}