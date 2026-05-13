package org.cdpg.dx.auth.v2.resolver;

import static org.junit.jupiter.api.Assertions.*;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.cdpg.dx.auth.v2.lookup.AppCredentialLookup;
import org.cdpg.dx.auth.v2.lookup.UserLookup;
import org.cdpg.dx.auth.v2.model.AppPrincipal;
import org.cdpg.dx.auth.v2.model.DxRole;
import org.cdpg.dx.auth.v2.model.Scopes;
import org.cdpg.dx.auth.v2.model.UserSnapshot;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("AppCredentialsResolver Tests")
class AppCredentialsResolverTest {

  private static AppCredentialLookup appReturns(AppPrincipal p) {
    return (id, secret) -> Future.succeededFuture(Optional.of(p));
  }

  private static AppCredentialLookup appNotFound() {
    return (id, secret) -> Future.succeededFuture(Optional.empty());
  }

  private static UserLookup userReturns(UserSnapshot u) {
    return sub -> Future.succeededFuture(Optional.of(u));
  }

  private static UserLookup userNotFound() {
    return sub -> Future.succeededFuture(Optional.empty());
  }

  @Nested
  @DisplayName("Happy path")
  class Happy {

    @Test
    @DisplayName("accepts X-App-Id / X-App-Secret headers and sets ctx.user() with app principal")
    void headersHappy() {
      AppPrincipal app =
          new AppPrincipal(
              "analytics-worker",
              "ananjay",
              "org-a",
              List.of(Scopes.OWN_ASSET_MANAGEMENT),
              0L,
              true);
      UserSnapshot owner =
          new UserSnapshot("ananjay", "org-a", Set.of(DxRole.PROVIDER), false);
      AppCredentialsResolver r =
          new AppCredentialsResolver(appReturns(app), userReturns(owner));

      FakeRoutingContext fake =
          new FakeRoutingContext()
              .header("X-App-Id", "analytics-worker")
              .header("X-App-Secret", "s3cret");

      r.resolve(fake.ctx);

      assertTrue(fake.nextCalled);
      assertNotNull(fake.currentUser, "ctx.setUser() must be called on success");

      JsonObject principal = fake.currentUser.principal();
      assertEquals("ananjay", principal.getString("sub"));
      assertEquals("org-a", principal.getString("organisation_id"));
      assertEquals("analytics-worker", principal.getString("app_id"));

      JsonArray scopes = principal.getJsonArray("scopes");
      assertNotNull(scopes);
      assertTrue(scopes.contains(Scopes.OWN_ASSET_MANAGEMENT),
          "Capped scopes must include own-asset-management");

      JsonArray roles = principal.getJsonObject("realm_access").getJsonArray("roles");
      assertTrue(roles.contains(DxRole.PROVIDER.keycloakName()),
          "Owner's roles must be present in principal");
    }

    @Test
    @DisplayName("accepts Authorization: Basic base64(appId:secret) fallback")
    void basicAuthFallback() {
      AppPrincipal app =
          new AppPrincipal(
              "worker", "ananjay", "org-a", List.of(Scopes.OWN_ASSET_MANAGEMENT), 0L, true);
      UserSnapshot owner =
          new UserSnapshot("ananjay", "org-a", Set.of(DxRole.PROVIDER), false);
      AppCredentialsResolver r =
          new AppCredentialsResolver(appReturns(app), userReturns(owner));

      String basic =
          "Basic "
              + Base64.getEncoder()
                  .encodeToString("worker:s3cret".getBytes(StandardCharsets.UTF_8));
      FakeRoutingContext fake = new FakeRoutingContext().header("Authorization", basic);

      r.resolve(fake.ctx);

      assertTrue(fake.nextCalled);
      assertNotNull(fake.currentUser);
    }
  }

  @Nested
  @DisplayName("Capping")
  class Capping {

    @Test
    @DisplayName("app.scopes ∩ owner.flattenedScopes — empty when owner lost role")
    void scopeCapShrinksWhenOwnerLostRole() {
      AppPrincipal app =
          new AppPrincipal(
              "worker",
              "ananjay",
              "org-a",
              List.of(Scopes.OWN_ASSET_MANAGEMENT, Scopes.ASSET_PUBLISH),
              0L,
              true);
      // Owner now only a CONSUMER → has only data-access → intersection with app scopes is empty
      UserSnapshot owner =
          new UserSnapshot("ananjay", "org-a", Set.of(DxRole.CONSUMER), false);
      AppCredentialsResolver r =
          new AppCredentialsResolver(appReturns(app), userReturns(owner));

      FakeRoutingContext fake =
          new FakeRoutingContext()
              .header("X-App-Id", "worker")
              .header("X-App-Secret", "s3cret");

      r.resolve(fake.ctx);

      assertTrue(fake.nextCalled);
      JsonArray scopes = fake.currentUser.principal().getJsonArray("scopes");
      assertTrue(scopes.isEmpty(), "Intersection must be empty when owner no longer has the scope");
    }
  }

  @Nested
  @DisplayName("Failure modes")
  class Failures {

    @Test
    @DisplayName("missing credentials → 401")
    void missingCreds() {
      AppCredentialsResolver r =
          new AppCredentialsResolver(appNotFound(), userNotFound());
      FakeRoutingContext fake = new FakeRoutingContext();
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }

    @Test
    @DisplayName("app lookup returns empty → 401")
    void appNotFoundUnauthorized() {
      AppCredentialsResolver r =
          new AppCredentialsResolver(
              appNotFound(),
              userReturns(new UserSnapshot("x", "y", Set.of(), false)));
      FakeRoutingContext fake =
          new FakeRoutingContext().header("X-App-Id", "w").header("X-App-Secret", "s");
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }

    @Test
    @DisplayName("app revoked (active=false) → 401")
    void revokedApp() {
      AppPrincipal revoked =
          new AppPrincipal("w", "ananjay", "org-a", List.of(), 0L, /*active*/ false);
      AppCredentialsResolver r =
          new AppCredentialsResolver(
              appReturns(revoked),
              userReturns(new UserSnapshot("ananjay", "org-a", Set.of(), false)));
      FakeRoutingContext fake =
          new FakeRoutingContext().header("X-App-Id", "w").header("X-App-Secret", "s");
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }

    @Test
    @DisplayName("owner disabled → 403")
    void ownerDisabled() {
      AppPrincipal app =
          new AppPrincipal(
              "w", "ananjay", "org-a", List.of(Scopes.OWN_ASSET_MANAGEMENT), 0L, true);
      UserSnapshot disabled =
          new UserSnapshot("ananjay", "org-a", Set.of(DxRole.PROVIDER), /*disabled*/ true);
      AppCredentialsResolver r =
          new AppCredentialsResolver(appReturns(app), userReturns(disabled));
      FakeRoutingContext fake =
          new FakeRoutingContext().header("X-App-Id", "w").header("X-App-Secret", "s");
      r.resolve(fake.ctx);
      assertInstanceOf(DxForbiddenException.class, fake.failedWith);
    }

    @Test
    @DisplayName("lookup transport failure → 401")
    void transportError() {
      AppCredentialLookup failing =
          (id, secret) -> Future.failedFuture(new RuntimeException("boom"));
      AppCredentialsResolver r =
          new AppCredentialsResolver(
              failing, userReturns(new UserSnapshot("x", "y", Set.of(), false)));
      FakeRoutingContext fake =
          new FakeRoutingContext().header("X-App-Id", "w").header("X-App-Secret", "s");
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }
  }
}