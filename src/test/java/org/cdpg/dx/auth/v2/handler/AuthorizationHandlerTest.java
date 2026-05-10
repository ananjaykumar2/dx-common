package org.cdpg.dx.auth.v2.handler;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.cdpg.dx.auth.v2.model.DxPrincipal;
import org.cdpg.dx.auth.v2.model.DxRole;
import org.cdpg.dx.auth.v2.model.Scopes;
import org.cdpg.dx.auth.v2.registry.InMemoryRoleScopeRegistry;
import org.cdpg.dx.auth.v2.registry.RoleScopeRegistry;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("AuthorizationHandler Tests")
class AuthorizationHandlerTest {

  private final RoleScopeRegistry registry = new InMemoryRoleScopeRegistry();
  private final AuthorizationHandler handler = new AuthorizationHandler(registry);

  /** Minimal fake routing context that tracks keys and next()/fail() calls. */
  private static class FakeCtx {
    final RoutingContext mock = mock(RoutingContext.class);
    final Map<String, Object> data = new HashMap<>();
    Throwable failedWith;
    boolean nextCalled;

    FakeCtx() {
      // getter/putter routed to our map
      when(mock.get(anyString())).thenAnswer(inv -> data.get(inv.<String>getArgument(0)));
      when(mock.put(anyString(), any()))
          .thenAnswer(
              inv -> {
                data.put(inv.getArgument(0), inv.getArgument(1));
                return mock;
              });
      doAnswer(
              inv -> {
                nextCalled = true;
                return null;
              })
          .when(mock)
          .next();
      doAnswer(
              inv -> {
                failedWith = inv.getArgument(0);
                return null;
              })
          .when(mock)
          .fail(any(Throwable.class));
    }

    FakeCtx withPrincipal(DxPrincipal p) {
      data.put(AuthorizationHandler.PRINCIPAL_KEY, p);
      return this;
    }
  }

  private DxPrincipal plainUser(DxRole... roles) {
    return DxPrincipal.builder()
        .authenticatedSub("alice")
        .authenticatedOrgId("org-a")
        .authorizationRoles(Set.of(roles))
        .auditRoles(Set.of(roles))
        .build();
  }

  @Nested
  @DisplayName("forScopes")
  class ForScopes {

    @Test
    @DisplayName("passes when any required scope is held")
    void anyMatch() {
      FakeCtx ctx = new FakeCtx().withPrincipal(plainUser(DxRole.ORG_ADMIN));
      handler.forScopes(Scopes.ORG_USER_MANAGEMENT).handle(ctx.mock);
      assertTrue(ctx.nextCalled);
      assertNull(ctx.failedWith);
    }

    @Test
    @DisplayName("passes when any of multiple required scopes is held")
    void anyOfMany() {
      FakeCtx ctx = new FakeCtx().withPrincipal(plainUser(DxRole.CONSUMER));
      handler.forScopes(Scopes.ASSET_PUBLISH, Scopes.DATA_ACCESS).handle(ctx.mock);
      assertTrue(ctx.nextCalled);
    }

    @Test
    @DisplayName("fails 403 when no required scope is held")
    void noMatchForbids() {
      FakeCtx ctx = new FakeCtx().withPrincipal(plainUser(DxRole.CONSUMER));
      handler.forScopes(Scopes.ORG_MANAGEMENT).handle(ctx.mock);
      assertFalse(ctx.nextCalled);
      assertInstanceOf(DxForbiddenException.class, ctx.failedWith);
    }

    @Test
    @DisplayName("fails 401 when no principal is present")
    void missingPrincipalUnauthorized() {
      FakeCtx ctx = new FakeCtx();
      handler.forScopes(Scopes.DATA_ACCESS).handle(ctx.mock);
      assertInstanceOf(DxUnauthorizedException.class, ctx.failedWith);
    }

    @Test
    @DisplayName("rejects empty required set at construction time")
    void rejectsEmpty() {
      assertThrows(IllegalArgumentException.class, () -> handler.forScopes());
    }
  }

  @Nested
  @DisplayName("forScopesWithContext")
  class ForScopesWithContext {

    @Test
    @DisplayName("PLATFORM rule wins when caller has platform-level scope — context has no filter")
    void platformTier() {
      FakeCtx ctx = new FakeCtx().withPrincipal(plainUser(DxRole.COS_ADMIN));
      handler
          .forScopesWithContext(
              ScopeRule.platform(Scopes.ORG_MANAGEMENT), ScopeRule.org(Scopes.ORG_USER_MANAGEMENT))
          .handle(ctx.mock);

      assertTrue(ctx.nextCalled);
      AuthorizationContext auth = (AuthorizationContext) ctx.data.get(AuthorizationContext.KEY);
      assertEquals(AuthLevel.PLATFORM, auth.getLevel());
      assertEquals(Scopes.ORG_MANAGEMENT, auth.getScope());
      assertNull(auth.getOrgId());
      assertNull(auth.getSub());
    }

    @Test
    @DisplayName("ORG rule wins when caller lacks platform scope — context carries orgId")
    void orgTier() {
      FakeCtx ctx = new FakeCtx().withPrincipal(plainUser(DxRole.ORG_ADMIN));
      handler
          .forScopesWithContext(
              ScopeRule.platform(Scopes.ORG_MANAGEMENT), ScopeRule.org(Scopes.ORG_USER_MANAGEMENT))
          .handle(ctx.mock);

      assertTrue(ctx.nextCalled);
      AuthorizationContext auth = (AuthorizationContext) ctx.data.get(AuthorizationContext.KEY);
      assertEquals(AuthLevel.ORG, auth.getLevel());
      assertEquals("org-a", auth.getOrgId());
    }

    @Test
    @DisplayName("priority order honored — PLATFORM matches even when ORG also matches")
    void priorityOrderMatters() {
      // Contrived: give caller both org-management (platform) and org-user-management (org).
      // PLATFORM rule is first → should win regardless of ORG presence.
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("alice")
              .authenticatedOrgId("org-a")
              .directScopes(Set.of(Scopes.ORG_MANAGEMENT, Scopes.ORG_USER_MANAGEMENT))
              .build();
      FakeCtx ctx = new FakeCtx().withPrincipal(p);

      handler
          .forScopesWithContext(
              ScopeRule.platform(Scopes.ORG_MANAGEMENT), ScopeRule.org(Scopes.ORG_USER_MANAGEMENT))
          .handle(ctx.mock);

      AuthorizationContext auth = (AuthorizationContext) ctx.data.get(AuthorizationContext.KEY);
      assertEquals(AuthLevel.PLATFORM, auth.getLevel(), "PLATFORM must win over ORG");
    }

    @Test
    @DisplayName("SELF rule — context carries effective sub")
    void selfTier() {
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("alice")
              .authenticatedOrgId("org-a")
              .directScopes(Set.of(Scopes.OWN_ASSET_MANAGEMENT))
              .build();
      FakeCtx ctx = new FakeCtx().withPrincipal(p);

      handler.forScopesWithContext(ScopeRule.self(Scopes.OWN_ASSET_MANAGEMENT)).handle(ctx.mock);

      AuthorizationContext auth = (AuthorizationContext) ctx.data.get(AuthorizationContext.KEY);
      assertEquals(AuthLevel.SELF, auth.getLevel());
      assertEquals("alice", auth.getSub());
    }

    @Test
    @DisplayName("no rule matches → 403")
    void noMatchForbids() {
      FakeCtx ctx = new FakeCtx().withPrincipal(plainUser(DxRole.CONSUMER));
      handler.forScopesWithContext(ScopeRule.platform(Scopes.ORG_MANAGEMENT)).handle(ctx.mock);
      assertInstanceOf(DxForbiddenException.class, ctx.failedWith);
    }
  }

  @Nested
  @DisplayName("forRoles")
  class ForRoles {

    @Test
    @DisplayName("plain user — checks authorizationRoles")
    void plainUserChecksAuthorizationRoles() {
      FakeCtx ctx = new FakeCtx().withPrincipal(plainUser(DxRole.COMPUTE));
      handler.forRoles(DxRole.COMPUTE).handle(ctx.mock);
      assertTrue(ctx.nextCalled);
    }

    @Test
    @DisplayName("delegation — checks auditRoles (empty authorizationRoles by design)")
    void delegationChecksAuditRoles() {
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("bob")
              .authenticatedOrgId("org-b")
              .delegatorSub("alice")
              .delegatorOrgId("org-a")
              .directScopes(Set.of(Scopes.DATA_ACCESS))
              .auditRoles(Set.of(DxRole.CONSUMER))
              .build();
      FakeCtx ctx = new FakeCtx().withPrincipal(p);
      handler.forRoles(DxRole.CONSUMER).handle(ctx.mock);
      assertTrue(ctx.nextCalled);
    }

    @Test
    @DisplayName("no matching role → 403")
    void noMatchForbids() {
      FakeCtx ctx = new FakeCtx().withPrincipal(plainUser(DxRole.CONSUMER));
      handler.forRoles(DxRole.COS_ADMIN).handle(ctx.mock);
      assertInstanceOf(DxForbiddenException.class, ctx.failedWith);
    }
  }

  @Nested
  @DisplayName("Constructor / input validation")
  class Validation {

    @Test
    @DisplayName("requires non-null registry")
    void nullRegistry() {
      assertThrows(NullPointerException.class, () -> new AuthorizationHandler(null));
    }

    @Test
    @DisplayName("forRoles rejects empty")
    void forRolesEmpty() {
      assertThrows(IllegalArgumentException.class, () -> handler.forRoles());
    }

    @Test
    @DisplayName("forScopesWithContext rejects empty")
    void forScopesWithContextEmpty() {
      assertThrows(IllegalArgumentException.class, () -> handler.forScopesWithContext());
    }
  }

  @SuppressWarnings("unused")
  private Handler<RoutingContext> typeCheck() {
    return handler.forScopes(Scopes.DATA_ACCESS);
  }
}
