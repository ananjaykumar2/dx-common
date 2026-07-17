package org.cdpg.dx.auth.handler;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.User;
import io.vertx.ext.web.RoutingContext;
import java.util.HashMap;
import java.util.Map;

import org.cdpg.dx.auth.authorization.model.AuthLevel;
import org.cdpg.dx.auth.authorization.model.AuthorizationContext;
import org.cdpg.dx.auth.authorization.handler.AuthorizationHandler;
import org.cdpg.dx.auth.authorization.model.ScopeRule;
import org.cdpg.dx.auth.model.DxRole;
import org.cdpg.dx.auth.model.Scopes;
import org.cdpg.dx.auth.authorization.registry.SystemRoleScopeMap;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("AuthorizationHandler Tests")
class AuthorizationHandlerTest {

  /** Minimal fake routing context that tracks ctx.user(), put/get, next(), and fail(). */
  private static class FakeCtx {
    final RoutingContext mock = mock(RoutingContext.class);
    final Map<String, Object> data = new HashMap<>();
    Throwable failedWith;
    boolean nextCalled;
    private User currentUser;

    FakeCtx() {
      HttpServerRequest request = mock(HttpServerRequest.class);
      when(request.path()).thenReturn("/test/path");
      when(mock.request()).thenReturn(request);
      when(mock.user()).thenAnswer(inv -> currentUser);
      when(mock.get(anyString())).thenAnswer(inv -> data.get(inv.<String>getArgument(0)));
      when(mock.put(anyString(), any()))
          .thenAnswer(inv -> {
            data.put(inv.getArgument(0), inv.getArgument(1));
            return mock;
          });
      doAnswer(inv -> { nextCalled = true; return null; }).when(mock).next();
      doAnswer(inv -> { failedWith = inv.getArgument(0); return null; })
          .when(mock).fail(any(Throwable.class));
    }

    FakeCtx withUser(JsonObject principal) {
      currentUser = User.create(principal);
      return this;
    }
  }

  private static JsonObject jwtPrincipal(String sub, String orgId, DxRole... roles) {
    JsonArray rolesArr = new JsonArray();
    JsonArray scopesArr = new JsonArray();
    for (DxRole role : roles) {
      rolesArr.add(role.value());
      SystemRoleScopeMap.getScopes(role).forEach(scopesArr::add);
    }
    return new JsonObject()
        .put("sub", sub)
        .put("organisation_id", orgId)
        .put("realm_access", new JsonObject().put("roles", rolesArr))
        .put("scopes", scopesArr);
  }

  private static JsonObject principalWithScopes(String sub, String orgId, String... scopes) {
    JsonArray scopesArr = new JsonArray();
    for (String s : scopes) scopesArr.add(s);
    return new JsonObject()
        .put("sub", sub)
        .put("organisation_id", orgId)
        .put("realm_access", new JsonObject().put("roles", new JsonArray()))
        .put("scopes", scopesArr);
  }

  @Nested
  @DisplayName("forScopes")
  class ForScopes {

    @Test
    @DisplayName("passes when any required scope is held")
    void anyMatch() {
      FakeCtx ctx = new FakeCtx().withUser(jwtPrincipal("alice", "org-a", DxRole.ORG_ADMIN));
      AuthorizationHandler.forScopes(Scopes.ORG_USER_MANAGEMENT).handle(ctx.mock);
      assertTrue(ctx.nextCalled);
      assertNull(ctx.failedWith);
    }

    @Test
    @DisplayName("passes when any of multiple required scopes is held")
    void anyOfMany() {
      FakeCtx ctx = new FakeCtx().withUser(jwtPrincipal("alice", "org-a", DxRole.CONSUMER));
      AuthorizationHandler.forScopes(Scopes.ASSET_PUBLISH, Scopes.DATA_ACCESS).handle(ctx.mock);
      assertTrue(ctx.nextCalled);
    }

    @Test
    @DisplayName("fails 403 when no required scope is held")
    void noMatchForbids() {
      FakeCtx ctx = new FakeCtx().withUser(jwtPrincipal("alice", "org-a", DxRole.CONSUMER));
      AuthorizationHandler.forScopes(Scopes.ORG_MANAGEMENT).handle(ctx.mock);
      assertFalse(ctx.nextCalled);
      assertInstanceOf(DxForbiddenException.class, ctx.failedWith);
    }

    @Test
    @DisplayName("fails 401 when no user is present")
    void missingUserUnauthorized() {
      FakeCtx ctx = new FakeCtx();
      AuthorizationHandler.forScopes(Scopes.DATA_ACCESS).handle(ctx.mock);
      assertInstanceOf(DxUnauthorizedException.class, ctx.failedWith);
    }

    @Test
    @DisplayName("rejects empty required set at construction time")
    void rejectsEmpty() {
      assertThrows(IllegalArgumentException.class, () -> AuthorizationHandler.forScopes());
    }
  }

  @Nested
  @DisplayName("forScopesWithContext")
  class ForScopesWithContext {

    @Test
    @DisplayName("PLATFORM rule wins when caller has platform-level scope")
    void platformTier() {
      FakeCtx ctx = new FakeCtx().withUser(jwtPrincipal("alice", "org-a", DxRole.COS_ADMIN));
      AuthorizationHandler.forScopesWithContext(
              ScopeRule.platform(Scopes.ORG_MANAGEMENT),
              ScopeRule.org(Scopes.ORG_USER_MANAGEMENT))
          .handle(ctx.mock);

      assertTrue(ctx.nextCalled);
      AuthorizationContext auth = (AuthorizationContext) ctx.data.get(AuthorizationContext.KEY);
      assertEquals(AuthLevel.PLATFORM, auth.getLevel());
      assertEquals(Scopes.ORG_MANAGEMENT, auth.getScope());
      assertNull(auth.getOrgId());
      assertNull(auth.getSub());
    }

    @Test
    @DisplayName("ORG rule wins when caller lacks platform scope")
    void orgTier() {
      FakeCtx ctx = new FakeCtx().withUser(jwtPrincipal("alice", "org-a", DxRole.ORG_ADMIN));
      AuthorizationHandler.forScopesWithContext(
              ScopeRule.platform(Scopes.ORG_MANAGEMENT),
              ScopeRule.org(Scopes.ORG_USER_MANAGEMENT))
          .handle(ctx.mock);

      assertTrue(ctx.nextCalled);
      AuthorizationContext auth = (AuthorizationContext) ctx.data.get(AuthorizationContext.KEY);
      assertEquals(AuthLevel.ORG, auth.getLevel());
      assertEquals("org-a", auth.getOrgId());
    }

    @Test
    @DisplayName("priority order honored — PLATFORM matches even when ORG also matches")
    void priorityOrderMatters() {
      FakeCtx ctx = new FakeCtx().withUser(
          principalWithScopes("alice", "org-a", Scopes.ORG_MANAGEMENT, Scopes.ORG_USER_MANAGEMENT));
      AuthorizationHandler.forScopesWithContext(
              ScopeRule.platform(Scopes.ORG_MANAGEMENT),
              ScopeRule.org(Scopes.ORG_USER_MANAGEMENT))
          .handle(ctx.mock);

      AuthorizationContext auth = (AuthorizationContext) ctx.data.get(AuthorizationContext.KEY);
      assertEquals(AuthLevel.PLATFORM, auth.getLevel(), "PLATFORM must win over ORG");
    }

    @Test
    @DisplayName("SELF rule — context carries effective sub")
    void selfTier() {
      FakeCtx ctx = new FakeCtx().withUser(
          principalWithScopes("alice", "org-a", Scopes.OWN_ASSET_MANAGEMENT));
      AuthorizationHandler.forScopesWithContext(ScopeRule.self(Scopes.OWN_ASSET_MANAGEMENT))
          .handle(ctx.mock);

      AuthorizationContext auth = (AuthorizationContext) ctx.data.get(AuthorizationContext.KEY);
      assertEquals(AuthLevel.SELF, auth.getLevel());
      assertEquals("alice", auth.getSub());
    }

    @Test
    @DisplayName("no rule matches → 403")
    void noMatchForbids() {
      FakeCtx ctx = new FakeCtx().withUser(jwtPrincipal("alice", "org-a", DxRole.CONSUMER));
      AuthorizationHandler.forScopesWithContext(ScopeRule.platform(Scopes.ORG_MANAGEMENT))
          .handle(ctx.mock);
      assertInstanceOf(DxForbiddenException.class, ctx.failedWith);
    }
  }

  @Nested
  @DisplayName("forRoles")
  class ForRoles {

    @Test
    @DisplayName("passes when user holds the required role")
    void roleMatch() {
      FakeCtx ctx = new FakeCtx().withUser(jwtPrincipal("alice", "org-a", DxRole.COMPUTE));
      AuthorizationHandler.forRoles(DxRole.COMPUTE).handle(ctx.mock);
      assertTrue(ctx.nextCalled);
    }

    @Test
    @DisplayName("delegation — roles from delegator's realm_access.roles")
    void delegationChecksRoles() {
      JsonObject principal = new JsonObject()
          .put("sub", "alice")
          .put("organisation_id", "org-a")
          .put("realm_access", new JsonObject().put("roles",
              new JsonArray().add(DxRole.CONSUMER.value())))
          .put("scopes", new JsonArray().add(Scopes.DATA_ACCESS))
          .put("delegatee_sub", "bob");
      FakeCtx ctx = new FakeCtx().withUser(principal);
      AuthorizationHandler.forRoles(DxRole.CONSUMER).handle(ctx.mock);
      assertTrue(ctx.nextCalled);
    }

    @Test
    @DisplayName("no matching role → 403")
    void noMatchForbids() {
      FakeCtx ctx = new FakeCtx().withUser(jwtPrincipal("alice", "org-a", DxRole.CONSUMER));
      AuthorizationHandler.forRoles(DxRole.COS_ADMIN).handle(ctx.mock);
      assertInstanceOf(DxForbiddenException.class, ctx.failedWith);
    }
  }

  @Nested
  @DisplayName("Input validation")
  class Validation {

    @Test
    @DisplayName("forScopes rejects empty")
    void forScopesEmpty() {
      assertThrows(IllegalArgumentException.class, () -> AuthorizationHandler.forScopes());
    }

    @Test
    @DisplayName("forRoles rejects empty")
    void forRolesEmpty() {
      assertThrows(IllegalArgumentException.class, () -> AuthorizationHandler.forRoles());
    }

    @Test
    @DisplayName("forScopesWithContext rejects empty")
    void forScopesWithContextEmpty() {
      assertThrows(IllegalArgumentException.class, () -> AuthorizationHandler.forScopesWithContext());
    }
  }

  @SuppressWarnings("unused")
  private Handler<RoutingContext> typeCheck() {
    return AuthorizationHandler.forScopes(Scopes.DATA_ACCESS);
  }
}