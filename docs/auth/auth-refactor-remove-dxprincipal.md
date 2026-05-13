# Auth Refactor: Deprecate DxPrincipal — Unify on Vert.x User + DxUser

## 1. Problem Statement

The current v2 auth stack has a structural inconsistency across the three authentication paths:

| Auth path | What is set in context | Used by v2 AuthorizationHandler |
|---|---|---|
| Plain JWT | `ctx.setUser(jwtUser)` | ❌ `ctx.get("dxPrincipal")` → **null → 401** |
| JWT + delegatorId | `ctx.setUser(delegationUser)` | ❌ `ctx.get("dxPrincipal")` → **null → 401** |
| appId + secret | `ctx.put("dxPrincipal", principal)` | ✅ works |

Only the app-credential path sets a `DxPrincipal`, so JWT and delegation requests fail authorization even after successful authentication. `DxPrincipal` also duplicates concerns already handled by Vert.x `User`, creating two parallel identity models in the same request lifecycle.

---

## 2. Strategy

**Fix v2 only. Leave existing (`auth/authorization/handler/AuthorizationHandler`) completely untouched.**

- The v2 `AuthorizationHandler` is rewritten to read from `ctx.user()` (Vert.x User) instead of `ctx.get("dxPrincipal")`.
- `DxPrincipal`, `RoleScopeRegistry`, and `InMemoryRoleScopeRegistry` are **deprecated** (not deleted) so existing code keeps compiling while v2 stabilises.
- Once v2 is working end-to-end, the existing `AuthorizationHandler` can be replaced by the v2 one.
- `DxUser` only gains new fields — **nothing is removed or renamed**.

---

## 3. Goals

1. **Single identity type from auth** — always Vert.x `User` from all three auth paths.
2. **Single pre-computed `scopes` field** in Vert.x User principal — no dual-field logic.
3. **No changes to API service layer** — services reading `RoutingContextHelper.getDxUser()` or `fromPrincipal()` are unaffected.
4. **`appId` and `delegateeId` travel end-to-end** — available for auditing from both Vert.x User and `DxUser`.
5. **Deprecate, not delete** — `DxPrincipal` and related classes get `@Deprecated`; existing `AuthorizationHandler` is untouched.

---

## 4. Scope Flattening — How v2 Does It (Retained)

`SystemRoleScopeMap` is a code-level constant mapping each system role to its authorised scopes:

| Role | Scopes |
|---|---|
| `consumer` | `data-access` |
| `provider` | `own-asset-management` |
| `org_admin` | `org-user-management`, `org-asset-management`, `org-asset-publish`, `org-publisher-management`, `own-asset-management` |
| `cos_admin` | `org-management`, `asset-publish`, `asset-management`, `user-management`, `publisher-management`, `role-management` |
| `compute` | `compute-access` |

This map is already used by `DelegationResolver` and `AppCredentialsResolver` to cap scopes. After the refactor it is also used by `AuthenticationHandlerV2` to pre-compute scopes for plain JWT users. No DB access required.

---

## 5. Unified Vert.x User Principal Structure

After the refactor every successful auth path produces a Vert.x `User` whose `principal()` has:

```jsonc
{
  // always present
  "sub":             "<effective user UUID>",
  "organisation_id": "<effective org UUID or null>",
  "realm_access": {
    "roles": ["consumer", "provider", ...]
  },
  "scopes": ["data-access", "own-asset-management", ...],  // pre-computed — see table below

  // delegation path only
  "delegatee_sub":    "<JWT sub — the person acting on behalf>",
  "delegatee_org_id": "<JWT org — optional>",

  // app path only
  "app_id": "<application identifier>",

  // plain JWT only — all original JWT claims preserved as-is
  // (email, name, kyc_verified, email_verified, preferred_username, ...)
}
```

### How `scopes` is computed per path

| Path | `sub` value | `scopes` computation |
|---|---|---|
| **Plain JWT** | JWT `sub` | `flatten(realm_access.roles)` via `SystemRoleScopeMap` |
| **JWT + delegatorId** | delegator's `sub` | `delegator_role_scopes ∩ delegation.scopes` (full delegator scopes if `fullDelegation=true`) |
| **appId + secret** | owner's `sub` | `owner_role_scopes ∩ app.appScopes` |

`delegation_scope` as a Keycloak JWT claim is no longer used. Scopes are always computed server-side.

---

## 6. DxUser Changes — Additive Only

Two nullable fields are appended. **No existing field is removed, renamed, or reordered. `toJson()` keeps all existing keys and adds two more.**

```java
public record DxUser(
    List<String>    roles,
    String          organisationId,
    String          organisationName,
    UUID            sub,
    boolean         emailVerified,
    boolean         kycVerified,
    String          name,
    String          preferredUsername,
    String          givenName,
    String          familyName,
    String          email,
    List<String>    pendingRoles,
    JsonObject      organisation,
    LocalDateTime   createdAt,
    JsonObject      kycData,
    String          twitter_account,
    String          linkedin_account,
    String          github_account,
    Boolean         account_enabled,
    String          did,
    String          aud,
    JsonArray       scopes,           // existing — unchanged
    // ── NEW (appended, nullable) ──
    String          delegateeId,      // null for JWT and app users; JWT sub for delegation
    String          appId             // null for JWT and delegation users; app id for app auth
)
```

### `toJson()` — additions only, existing keys untouched

```java
// existing keys kept as-is:
.put("delegation_scope", scopes != null ? scopes : new JsonArray())
// new keys appended:
.put("delegateeId", delegateeId)
.put("appId", appId)
```

### `withPendingRoles()` — thread new fields through unchanged

```java
public static DxUser withPendingRoles(DxUser user, List<String> pendingRoles, JsonObject organisation) {
    return new DxUser(
        user.roles(),
        user.organisationId(),
        user.organisationName(),
        user.sub(),
        user.emailVerified(),
        user.kycVerified(),
        user.name(),
        user.preferredUsername(),
        user.givenName(),
        user.familyName(),
        user.email(),
        pendingRoles,
        organisation,
        user.createdAt(),
        user.kycData(),
        user.twitter_account(),
        user.linkedin_account(),
        user.github_account(),
        user.account_enabled(),
        user.did(),
        user.aud(),
        user.scopes(),
        user.delegateeId(),   // preserved
        user.appId()          // preserved
    );
}
```

---

## 7. File-by-File Changes

### 7.1 `AuthenticationHandlerV2` — enrich JWT User with pre-computed scopes

**Current (JWT bare path):**
```java
.onSuccess(user -> {
    ctx.setUser(user);   // raw JWT claims, no scopes field
    if (delegatorHeader != null ...) delegationResolver.resolve(ctx);
    else ctx.next();
})
```

**After:**
```java
.onSuccess(user -> {
    User enriched = enrichWithScopes(user);
    ctx.setUser(enriched);
    if (delegatorHeader != null && !delegatorHeader.isBlank()) {
        delegationResolver.resolve(ctx);
    } else {
        ctx.next();
    }
})
```

New private helper (add imports for `DxRole`, `SystemRoleScopeMap`):
```java
private static User enrichWithScopes(User jwtUser) {
    JsonObject principal = jwtUser.principal().copy();
    JsonArray roles = principal
        .getJsonObject("realm_access", new JsonObject())
        .getJsonArray("roles", new JsonArray());

    Set<String> scopeSet = new HashSet<>();
    for (Object r : roles) {
        DxRole.fromKeycloakName(r.toString())
              .ifPresent(role -> scopeSet.addAll(SystemRoleScopeMap.getScopes(role)));
    }

    JsonArray scopesArr = new JsonArray();
    scopeSet.forEach(scopesArr::add);
    principal.put("scopes", scopesArr);

    return User.create(principal);
}
```

### 7.2 `DelegationResolver` — rename `delegation_scope` → `scopes` in built Vert.x User

Only the key name changes inside `buildUser()`. All logic remains identical.

```java
// Before:
.put("delegation_scope", scopesArr)

// After:
.put("scopes", scopesArr)
```

The `delegatee_sub` and conditional `delegatee_org_id` fields stay as-is.

### 7.3 `AppCredentialsResolver` — replace `DxPrincipal` with `ctx.setUser()`

**Remove:**
- Import of `DxPrincipal`
- Import of v2 `AuthorizationHandler` (and `PRINCIPAL_KEY`)
- `buildPrincipal()` method
- `ctx.put(AuthorizationHandler.PRINCIPAL_KEY, principal)` call

**Add `buildUser()` in its place:**
```java
private User buildUser(AppPrincipal app, UserSnapshot owner) {
    Set<String> ownerCurrentScopes = flatten(owner.roles());
    Set<String> capped = intersect(app.appScopes(), ownerCurrentScopes);
    String ownerOrgId = app.ownerOrgId() != null ? app.ownerOrgId() : owner.organisationId();

    JsonArray rolesArr = new JsonArray();
    owner.roles().forEach(r -> rolesArr.add(r.keycloakName()));

    JsonArray scopesArr = new JsonArray();
    capped.forEach(scopesArr::add);

    JsonObject principal = new JsonObject()
        .put("sub",             owner.sub())
        .put("organisation_id", ownerOrgId)
        .put("realm_access",    new JsonObject().put("roles", rolesArr))
        .put("scopes",          scopesArr)
        .put("app_id",          app.appId());

    return User.create(principal);
}
```

Call site in `resolve()` becomes:
```java
User user = buildUser(app, owner);
LOGGER.debug("app user principal: {}", user.principal());
ctx.setUser(user);
ctx.next();
```

### 7.4 `v2/handler/AuthorizationHandler` — rewrite to use Vert.x User, keep `DxPrincipal` path deprecated

The v2 `AuthorizationHandler` is rewritten to read from `ctx.user()`. The old `PRINCIPAL_KEY` constant and `getPrincipal()` helper are kept but marked `@Deprecated` so callers still compile.

```java
public final class AuthorizationHandler {

  private static final Logger LOGGER = LogManager.getLogger(AuthorizationHandler.class);

  /** @deprecated No longer populated. All auth paths now set ctx.user() directly. */
  @Deprecated
  public static final String PRINCIPAL_KEY = "dxPrincipal";

  private final RoleScopeRegistry registry;

  public AuthorizationHandler(RoleScopeRegistry registry) {
    this.registry = Objects.requireNonNull(registry, "registry");
  }

  /**
   * Passes if the user's pre-computed scopes contain any of the required scopes.
   * Works for plain JWT, delegation, and app-credential users — all three paths
   * now pre-compute scopes under the "scopes" key in the Vert.x User principal.
   */
  public Handler<RoutingContext> forScopes(String... required) {
    if (required == null || required.length == 0)
      throw new IllegalArgumentException("forScopes requires at least one scope");

    Set<String> requiredSet = new HashSet<>(Arrays.asList(required));

    return ctx -> {
      User user = getUser(ctx);
      if (user == null) return;

      JsonArray scopes = user.principal().getJsonArray("scopes", new JsonArray());
      LOGGER.debug("Effective scopes: {}", scopes);

      boolean match = scopes.stream()
          .map(Object::toString)
          .anyMatch(requiredSet::contains);

      if (match) {
        ctx.next();
      } else {
        ctx.fail(new DxForbiddenException("Insufficient scope"));
      }
    };
  }

  /**
   * Passes if the user's roles (from realm_access.roles in Vert.x User principal)
   * contain any of the required roles.
   */
  public Handler<RoutingContext> forRoles(DxRole... required) {
    if (required == null || required.length == 0)
      throw new IllegalArgumentException("forRoles requires at least one role");

    Set<String> requiredNames = Arrays.stream(required)
        .map(DxRole::keycloakName)
        .collect(Collectors.toSet());

    return ctx -> {
      User user = getUser(ctx);
      if (user == null) return;

      JsonArray roles = user.principal()
          .getJsonObject("realm_access", new JsonObject())
          .getJsonArray("roles", new JsonArray());

      boolean match = roles.stream()
          .map(Object::toString)
          .anyMatch(requiredNames::contains);

      if (match) {
        ctx.next();
      } else {
        ctx.fail(new DxForbiddenException("User does not hold the required role"));
      }
    };
  }

  /**
   * Same as forScopes but also publishes an AuthorizationContext for downstream
   * services to branch on (PLATFORM / ORG / SELF).
   */
  public Handler<RoutingContext> forScopesWithContext(ScopeRule... rules) {
    if (rules == null || rules.length == 0)
      throw new IllegalArgumentException("forScopesWithContext requires at least one rule");

    return ctx -> {
      User user = getUser(ctx);
      if (user == null) return;

      JsonArray scopes = user.principal().getJsonArray("scopes", new JsonArray());
      Set<String> effectiveScopes = scopes.stream()
          .map(Object::toString)
          .collect(Collectors.toSet());

      String sub = user.principal().getString("sub");
      String orgId = user.principal().getString("organisation_id");

      for (ScopeRule rule : rules) {
        if (effectiveScopes.contains(rule.scope())) {
          AuthorizationContext authCtx = switch (rule.level()) {
            case PLATFORM -> AuthorizationContext.platform(rule.scope());
            case ORG     -> AuthorizationContext.org(rule.scope(), orgId);
            case SELF    -> AuthorizationContext.self(rule.scope(), sub);
          };
          ctx.put(AuthorizationContext.KEY, authCtx);
          ctx.next();
          return;
        }
      }
      ctx.fail(new DxForbiddenException("Insufficient scope"));
    };
  }

  private User getUser(RoutingContext ctx) {
    User user = ctx.user();
    if (user == null) {
      ctx.fail(new DxUnauthorizedException("No authenticated user"));
      return null;
    }
    LOGGER.debug("Authenticated user principal: {}", user.principal());
    return user;
  }

  /** @deprecated Use getUser(ctx) — all paths now set ctx.user() directly. */
  @Deprecated
  private DxPrincipal getPrincipal(RoutingContext ctx) {
    return ctx.get(PRINCIPAL_KEY);
  }
}
```

> Note: The `registry` field and its constructor argument are kept to avoid breaking callers that already construct `AuthorizationHandler(registry)`. The registry is no longer called internally but removing it would be a breaking change — deprecate it in a follow-up.

### 7.5 `RoutingContextHelper.fromPrincipal()` — read `scopes`, `delegatee_sub`, `app_id`

```java
public static DxUser fromPrincipal(RoutingContext ctx) {
    JsonObject principal = ctx.user().principal();

    List<String> roles = principal
        .getJsonObject("realm_access", new JsonObject())
        .getJsonArray("roles", new JsonArray())
        .getList();

    UUID userId;
    try {
        userId = UUID.fromString(principal.getString("sub"));
    } catch (IllegalArgumentException | NullPointerException e) {
        throw new DxBadRequestException("Invalid or missing 'sub' UUID in token");
    }

    // new fields — null-safe
    JsonArray scopes     = principal.getJsonArray("scopes", new JsonArray());
    String delegateeId   = principal.getString("delegatee_sub", null);
    String appId         = principal.getString("app_id", null);

    return new DxUser(
        roles,
        principal.getString("organisation_id", null),
        principal.getString("organisation_name", null),
        userId,
        principal.getBoolean("email_verified", false),
        principal.getBoolean("kyc_verified", false),
        principal.getString("name"),
        principal.getString("preferred_username"),
        principal.getString("given_name"),
        principal.getString("family_name"),
        principal.getString("email"),
        new ArrayList<>(),
        new JsonObject(),
        null,
        new JsonObject(),
        "",
        "",
        "",
        null,
        principal.getString("did", null),
        principal.getString("aud", null),
        scopes,        // pre-computed from Vert.x User
        delegateeId,   // null for plain JWT
        appId          // null for plain JWT and delegation
    );
}
```

---

## 8. Deprecations (Not Deletions)

| Class / Member | Deprecation note |
|---|---|
| `DxPrincipal` | `@Deprecated` on class — use Vert.x `User` + `DxUser` |
| `v2/handler/AuthorizationHandler.PRINCIPAL_KEY` | `@Deprecated` — no longer populated |
| `v2/handler/AuthorizationHandler.getPrincipal()` | `@Deprecated` — use `getUser()` |
| `RoleScopeRegistry` interface | `@Deprecated` — scope resolution is now done at auth time, not authorization time |
| `InMemoryRoleScopeRegistry` | `@Deprecated` — same reason |
| `v2/handler/AuthorizationHandler` constructor's `registry` arg | `@Deprecated` — kept for binary compat, no longer called |

None of these are deleted. They will be removed in a follow-up once v2 replaces the main handler.

---

## 9. Files Changed Summary

| File | Change type |
|---|---|
| `auth/v2/handler/AuthenticationHandlerV2.java` | Modified — add `enrichWithScopes()` |
| `auth/v2/resolver/DelegationResolver.java` | Modified — `delegation_scope` → `scopes` key |
| `auth/v2/resolver/AppCredentialsResolver.java` | Modified — replace `DxPrincipal` with `ctx.setUser()` |
| `auth/v2/handler/AuthorizationHandler.java` | Rewritten — uses `ctx.user()`, deprecates old internals |
| `auth/v2/model/DxPrincipal.java` | Deprecate with `@Deprecated` on class |
| `auth/v2/registry/RoleScopeRegistry.java` | Deprecate with `@Deprecated` on interface |
| `auth/v2/registry/InMemoryRoleScopeRegistry.java` | Deprecate with `@Deprecated` on class |
| `common/model/DxUser.java` | Add `delegateeId`, `appId` fields + update `toJson()` and `withPendingRoles()` |
| `common/util/RoutingContextHelper.java` | Update `fromPrincipal()` to read new fields |
| `auth/authorization/handler/AuthorizationHandler.java` | **No change** |

---

## 10. Test Changes

### `DxUserTest.java`
- Append `null, null` (for `delegateeId`, `appId`) to all `new DxUser(...)` calls in existing tests.
- Add assertions for `delegateeId` and `appId` in `serializesAllFields()`.

### `AppCredentialsResolverTest.java`
- Remove any assertion on `ctx.get("dxPrincipal")`.
- Assert `ctx.user()` is non-null after resolve.
- Assert `ctx.user().principal().getString("app_id")` equals the test app id.
- Assert `ctx.user().principal().getJsonArray("scopes")` contains the expected capped scopes.

### `DelegationResolverTest.java`
- Assert `ctx.user().principal().getJsonArray("scopes")` (not `delegation_scope`).
- Assert `ctx.user().principal().getString("delegatee_sub")` equals the JWT sub.

### `v2/handler/AuthorizationHandlerTest.java`
- Rewrite to test the new implementation (uses `ctx.user()` instead of `ctx.get("dxPrincipal")`).

### New test for `AuthenticationHandlerV2` scope enrichment
- Stub a JWT User with `realm_access.roles: ["consumer", "provider"]`.
- Assert enriched user has `scopes` containing `data-access` and `own-asset-management`.

---

## 11. Implementation Order

1. `DxUser.java` — add 2 fields, update `toJson()` and `withPendingRoles()`
2. `DxUserTest.java` — fix constructors, add assertions
3. `DxPrincipal.java` — add `@Deprecated` on class
4. `RoleScopeRegistry.java` — add `@Deprecated` on interface
5. `InMemoryRoleScopeRegistry.java` — add `@Deprecated` on class
6. `DelegationResolver.java` — rename `delegation_scope` → `scopes`
7. `AppCredentialsResolver.java` — replace `buildPrincipal()` with `buildUser()` + `ctx.setUser()`
8. `AuthenticationHandlerV2.java` — add `enrichWithScopes()`, wire into JWT success path
9. `v2/handler/AuthorizationHandler.java` — rewrite body, deprecate old members
10. `RoutingContextHelper.fromPrincipal()` — read `scopes`, `delegatee_sub`, `app_id`
11. Fix test files
12. Full test suite — fix any remaining compilation errors

---

## 12. Resolved Decisions

| Question | Decision |
|---|---|
| Delete or deprecate `DxPrincipal`? | **Deprecate** — keep compiling, remove in follow-up |
| Touch existing `auth/authorization/handler/AuthorizationHandler`? | **No** — untouched |
| Remove fields from `DxUser`? | **No** — additive only |
| Rename `delegation_scope` key in `DxUser.toJson()`? | **No** — keep existing key, add `delegateeId` and `appId` as new keys |
| Where does `forScopes()` live? | **v2 `AuthorizationHandler`** only — existing handler unchanged |