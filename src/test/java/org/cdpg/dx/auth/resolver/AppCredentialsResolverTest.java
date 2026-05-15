package org.cdpg.dx.auth.resolver;

import static org.junit.jupiter.api.Assertions.*;

import io.vertx.core.Future;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.cdpg.dx.auth.authentication.lookup.AppCredentialLookup;
import org.cdpg.dx.auth.authentication.lookup.UserLookup;
import org.cdpg.dx.auth.authentication.resolver.AppCredentialsResolver;
import org.cdpg.dx.auth.model.AppPrincipal;
import org.cdpg.dx.auth.model.Scopes;
import org.cdpg.dx.common.exception.DxForbiddenException;
import org.cdpg.dx.common.exception.DxUnauthorizedException;
import org.cdpg.dx.common.model.DxUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("AppCredentialsResolver Tests")
class AppCredentialsResolverTest {

  static final UUID OWNER_UUID = UUID.fromString("00000000-0000-0000-0000-000000000001");

  private static DxUser user(UUID sub, String orgId, boolean enabled, String... roles) {
    return new DxUser(
        Arrays.asList(roles), orgId, null, sub,
        false, false, null, null, null, null, null,
        null, null, null, null, null, null, null,
        enabled, null, null, null, null, null);
  }

  private static AppCredentialLookup appReturns(AppPrincipal p) {
    return (id, secret) -> Future.succeededFuture(Optional.of(p));
  }

  private static AppCredentialLookup appNotFound() {
    return (id, secret) -> Future.succeededFuture(Optional.empty());
  }

  private static UserLookup userReturns(DxUser u) {
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
              OWNER_UUID.toString(),
              "org-a",
              List.of(Scopes.OWN_ASSET_MANAGEMENT),
              0L,
              true);
      DxUser owner = user(OWNER_UUID, "org-a", true, "provider");
      AppCredentialsResolver r = new AppCredentialsResolver(appReturns(app), userReturns(owner));

      FakeRoutingContext fake =
          new FakeRoutingContext()
              .header("X-App-Id", "analytics-worker")
              .header("X-App-Secret", "s3cret");

      r.resolve(fake.ctx);

      assertTrue(fake.nextCalled);
      assertNotNull(fake.currentUser, "ctx.setUser() must be called on success");

      JsonObject principal = fake.currentUser.principal();
      assertEquals(OWNER_UUID.toString(), principal.getString("sub"));
      assertEquals("org-a", principal.getString("organisation_id"));
      assertEquals("analytics-worker", principal.getString("app_id"));

      JsonArray scopes = principal.getJsonArray("scopes");
      assertNotNull(scopes);
      assertTrue(scopes.contains(Scopes.OWN_ASSET_MANAGEMENT),
          "Capped scopes must include own-asset-management");

      JsonArray roles = principal.getJsonObject("realm_access").getJsonArray("roles");
      assertTrue(roles.contains("provider"), "Owner's roles must be present in principal");
    }

    @Test
    @DisplayName("accepts Authorization: Basic base64(appId:secret) fallback")
    void basicAuthFallback() {
      AppPrincipal app =
          new AppPrincipal("worker", OWNER_UUID.toString(), "org-a",
              List.of(Scopes.OWN_ASSET_MANAGEMENT), 0L, true);
      DxUser owner = user(OWNER_UUID, "org-a", true, "provider");
      AppCredentialsResolver r = new AppCredentialsResolver(appReturns(app), userReturns(owner));

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
          new AppPrincipal("worker", OWNER_UUID.toString(), "org-a",
              List.of(Scopes.OWN_ASSET_MANAGEMENT, Scopes.ASSET_PUBLISH), 0L, true);
      DxUser owner = user(OWNER_UUID, "org-a", true, "consumer");
      AppCredentialsResolver r = new AppCredentialsResolver(appReturns(app), userReturns(owner));

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
      AppCredentialsResolver r = new AppCredentialsResolver(appNotFound(), userNotFound());
      FakeRoutingContext fake = new FakeRoutingContext();
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }

    @Test
    @DisplayName("app lookup returns empty → 401")
    void appNotFoundUnauthorized() {
      AppCredentialsResolver r =
          new AppCredentialsResolver(appNotFound(), userReturns(user(OWNER_UUID, "org-a", true)));
      FakeRoutingContext fake =
          new FakeRoutingContext().header("X-App-Id", "w").header("X-App-Secret", "s");
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }

    @Test
    @DisplayName("app revoked (active=false) → 401")
    void revokedApp() {
      AppPrincipal revoked =
          new AppPrincipal("w", OWNER_UUID.toString(), "org-a", List.of(), 0L, false);
      AppCredentialsResolver r =
          new AppCredentialsResolver(appReturns(revoked), userReturns(user(OWNER_UUID, "org-a", true)));
      FakeRoutingContext fake =
          new FakeRoutingContext().header("X-App-Id", "w").header("X-App-Secret", "s");
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }

    @Test
    @DisplayName("owner disabled → 403")
    void ownerDisabled() {
      AppPrincipal app =
          new AppPrincipal("w", OWNER_UUID.toString(), "org-a",
              List.of(Scopes.OWN_ASSET_MANAGEMENT), 0L, true);
      DxUser disabled = user(OWNER_UUID, "org-a", false, "provider");
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
          new AppCredentialsResolver(failing, userReturns(user(OWNER_UUID, "org-a", true)));
      FakeRoutingContext fake =
          new FakeRoutingContext().header("X-App-Id", "w").header("X-App-Secret", "s");
      r.resolve(fake.ctx);
      assertInstanceOf(DxUnauthorizedException.class, fake.failedWith);
    }
  }
}