package org.cdpg.dx.auth.resolver;

import static org.junit.jupiter.api.Assertions.*;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.cdpg.dx.auth.authentication.lookup.DelegationLookup;
import org.cdpg.dx.auth.authentication.lookup.UserLookup;
import org.cdpg.dx.auth.authentication.resolver.DelegationResolver;
import org.cdpg.dx.auth.model.DelegationRecord;
import org.cdpg.dx.auth.model.DxRole;
import org.cdpg.dx.auth.model.Scopes;
import org.cdpg.dx.auth.model.UserSnapshot;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("DelegationResolver Tests")
class DelegationResolverTest {

  private static JsonObject jwt(String sub, String org, String... roles) {
    JsonArray rolesArr = new JsonArray();
    for (String r : roles) rolesArr.add(r);
    return new JsonObject()
        .put("sub", sub)
        .put("organisation_id", org)
        .put("realm_access", new JsonObject().put("roles", rolesArr));
  }

  private static DelegationLookup delReturns(DelegationRecord d) {
    return (delegator, delegatee) -> Future.succeededFuture(Optional.of(d));
  }

  private static DelegationLookup delNotFound() {
    return (delegator, delegatee) -> Future.succeededFuture(Optional.empty());
  }

  private static UserLookup userReturns(UserSnapshot u) {
    return sub -> Future.succeededFuture(Optional.of(u));
  }

  @Nested
  @DisplayName("Happy path")
  class Happy {

    @Test
    @DisplayName("partial delegation — ctx.user() is set to delegator with capped scopes")
    void partialDelegationHappy() {
      DelegationRecord d =
          new DelegationRecord(
              "alice", "bob", Set.of(Scopes.DATA_ACCESS), false, true, 0L);
      // Alice is Consumer + OrgAdmin — so she has data-access
      UserSnapshot alice =
          new UserSnapshot(
              "alice", "org-a", Set.of(DxRole.CONSUMER, DxRole.ORG_ADMIN), false);
      DelegationResolver r = new DelegationResolver(delReturns(d), userReturns(alice));

      FakeRoutingContext fake =
          new FakeRoutingContext()
              .userWithClaims(jwt("bob", "org-b", "provider"))
              .header("did", "alice");

      r.resolve(fake.ctx);

      assertTrue(fake.nextCalled);
      assertNotNull(fake.currentUser, "ctx.setUser() must be called on success");

      JsonObject principal = fake.currentUser.principal();
      // effective identity is the delegator
      assertEquals("alice", principal.getString("sub"));
      assertEquals("org-a", principal.getString("organisation_id"));
      // delegatee stored for audit
      assertEquals("bob", principal.getString("delegatee_sub"));
      // scopes capped to delegation grant ∩ delegator's current scopes
      JsonArray scopes = principal.getJsonArray("scopes");
      assertNotNull(scopes);
      assertTrue(scopes.contains(Scopes.DATA_ACCESS));
    }

    @Test
    @DisplayName("full delegation — scopes equal delegator's current flattened scopes")
    void fullDelegationTracksDelegator() {
      DelegationRecord d =
          new DelegationRecord("alice", "bob", Set.of(), /*fullDelegation*/ true, true, 0L);
      UserSnapshot alice =
          new UserSnapshot("alice", "org-a", Set.of(DxRole.PROVIDER), false);
      DelegationResolver r = new DelegationResolver(delReturns(d), userReturns(alice));

      FakeRoutingContext fake =
          new FakeRoutingContext()
              .userWithClaims(jwt("bob", "org-b", "provider"))
              .header("did", "alice");

      r.resolve(fake.ctx);

      assertTrue(fake.nextCalled);
      JsonArray scopes = fake.currentUser.principal().getJsonArray("scopes");
      assertTrue(scopes.contains(Scopes.OWN_ASSET_MANAGEMENT),
          "Full delegation must grant all of delegator's current scopes");
    }
  }

  @Nested
  @DisplayName("Capping")
  class Capping {

    @Test
    @DisplayName("partial delegation scope absent from delegator's current roles → capped out")
    void scopeDroppedWhenDelegatorLostRole() {
      // Delegation grants data-access, but Alice is now only a Provider (no data-access)
      DelegationRecord d =
          new DelegationRecord("alice", "bob", Set.of(Scopes.DATA_ACCESS), false, true, 0L);
      UserSnapshot alice =
          new UserSnapshot("alice", "org-a", Set.of(DxRole.PROVIDER), false);
      DelegationResolver r = new DelegationResolver(delReturns(d), userReturns(alice));

      FakeRoutingContext fake =
          new FakeRoutingContext()
              .userWithClaims(jwt("bob", "org-b", "provider"))
              .header("did", "alice");

      r.resolve(fake.ctx);

      assertTrue(fake.nextCalled);
      JsonArray scopes = fake.currentUser.principal().getJsonArray("scopes");
      assertFalse(scopes.contains(Scopes.DATA_ACCESS),
          "Scope must be dropped when delegator no longer holds that role");
    }
  }

  @Nested
  @DisplayName("Failure modes")
  class Failures {

    @Test
    @DisplayName("missing did header → 401")
    void missingHeader() {
      DelegationResolver r =
          new DelegationResolver(
              delNotFound(),
              userReturns(new UserSnapshot("alice", "org-a", Set.of(), false)));
      FakeRoutingContext fake =
          new FakeRoutingContext().userWithClaims(jwt("bob", "org-b"));
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }

    @Test
    @DisplayName("no active delegation → 403")
    void noActiveDelegation() {
      DelegationResolver r =
          new DelegationResolver(
              delNotFound(),
              userReturns(new UserSnapshot("alice", "org-a", Set.of(), false)));
      FakeRoutingContext fake =
          new FakeRoutingContext()
              .userWithClaims(jwt("bob", "org-b"))
              .header("did", "alice");
      r.resolve(fake.ctx);
      assertInstanceOf(DxForbiddenException.class, fake.failedWith);
    }

    @Test
    @DisplayName("inactive delegation record → 403")
    void delegationMarkedInactive() {
      DelegationRecord inactive =
          new DelegationRecord("alice", "bob", Set.of(), true, /*active*/ false, 0L);
      DelegationResolver r =
          new DelegationResolver(
              delReturns(inactive),
              userReturns(new UserSnapshot("alice", "org-a", Set.of(), false)));
      FakeRoutingContext fake =
          new FakeRoutingContext()
              .userWithClaims(jwt("bob", "org-b"))
              .header("did", "alice");
      r.resolve(fake.ctx);
      assertInstanceOf(DxForbiddenException.class, fake.failedWith);
    }

    @Test
    @DisplayName("expired delegation → 403")
    void expiredDelegation() {
      long expired = Instant.now().getEpochSecond() - 3600;
      DelegationRecord d =
          new DelegationRecord("alice", "bob", Set.of(), true, true, expired);
      DelegationResolver r =
          new DelegationResolver(
              delReturns(d),
              userReturns(new UserSnapshot("alice", "org-a", Set.of(DxRole.PROVIDER), false)));
      FakeRoutingContext fake =
          new FakeRoutingContext()
              .userWithClaims(jwt("bob", "org-b"))
              .header("did", "alice");
      r.resolve(fake.ctx);
      assertInstanceOf(DxForbiddenException.class, fake.failedWith);
    }

    @Test
    @DisplayName("delegator disabled → 403")
    void delegatorDisabled() {
      DelegationRecord d =
          new DelegationRecord("alice", "bob", Set.of(), true, true, 0L);
      UserSnapshot disabled =
          new UserSnapshot("alice", "org-a", Set.of(DxRole.PROVIDER), /*disabled*/ true);
      DelegationResolver r =
          new DelegationResolver(delReturns(d), userReturns(disabled));
      FakeRoutingContext fake =
          new FakeRoutingContext()
              .userWithClaims(jwt("bob", "org-b"))
              .header("did", "alice");
      r.resolve(fake.ctx);
      assertInstanceOf(DxForbiddenException.class, fake.failedWith);
    }

    @Test
    @DisplayName("missing JWT user → 401")
    void missingUser() {
      DelegationResolver r =
          new DelegationResolver(
              delNotFound(),
              userReturns(new UserSnapshot("x", "y", Set.of(), false)));
      FakeRoutingContext fake =
          new FakeRoutingContext().noUser().header("did", "alice");
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }
  }
}