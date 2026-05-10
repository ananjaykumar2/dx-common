package org.cdpg.dx.auth.v2.model;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.util.Set;

/**
 * Uniform principal produced by every authentication path (plain user JWT, delegation, app
 * credentials). Downstream code reads this without knowing which path built it.
 *
 * <p>Invariants enforced by the builder:
 *
 * <ul>
 *   <li>Exactly one effective {@code sub} per principal; {@code orgId} is optional.
 *   <li>{@code authorizationRoles} is populated for the plain-user path only; empty for delegation
 *       and app principals (their effective scopes live in {@code directScopes}, already capped).
 *   <li>{@code auditRoles} is separate from {@code authorizationRoles}: audit never feeds back into
 *       authorization.
 *   <li>Delegation and app are mutually exclusive: a principal cannot be both.
 * </ul>
 */
public final class DxPrincipal {

  private final String authenticatedSub;
  private final String authenticatedOrgId;
  private final String delegatorSub;
  private final String delegatorOrgId;
  private final Set<DxRole> authorizationRoles;
  private final Set<String> directScopes;
  private final Set<DxRole> auditRoles;
  private final String appId;

  private DxPrincipal(Builder b) {
    this.authenticatedSub = b.authenticatedSub;
    this.authenticatedOrgId = b.authenticatedOrgId;
    this.delegatorSub = b.delegatorSub;
    this.delegatorOrgId = b.delegatorOrgId;
    this.authorizationRoles = Set.copyOf(b.authorizationRoles);
    this.directScopes = Set.copyOf(b.directScopes);
    this.auditRoles = Set.copyOf(b.auditRoles);
    this.appId = b.appId;

    if ((delegatorSub == null) != (delegatorOrgId == null)) {
      throw new IllegalArgumentException(
          "delegatorSub and delegatorOrgId must both be set or both be null");
    }
    if (delegatorSub != null && appId != null) {
      throw new IllegalArgumentException(
          "A principal cannot be both a delegation and an app — pick one");
    }
  }

  /** Effective identity whose data and authority apply to this request. */
  public String getSub() {
    return delegatorSub != null ? delegatorSub : authenticatedSub;
  }

  /** Effective organisation whose boundary applies to this request. */
  public String getOrganisationId() {
    return delegatorOrgId != null ? delegatorOrgId : authenticatedOrgId;
  }

  public String getAuthenticatedSub() {
    return authenticatedSub;
  }

  public String getAuthenticatedOrgId() {
    return authenticatedOrgId;
  }

  public boolean isDelegation() {
    return delegatorSub != null;
  }

  public boolean isApp() {
    return appId != null;
  }

  public boolean isDirectUser() {
    return !isDelegation() && !isApp();
  }

  public Set<DxRole> getAuditRoles() {
    return auditRoles;
  }

  public String getAppId() {
    return appId;
  }

  public Set<DxRole> getAuthorizationRoles() {
    return authorizationRoles;
  }

  public Set<String> getDirectScopes() {
    return directScopes;
  }

  /** Convert this principal to JsonObject (for API response, logging, context storage, etc.) */
  public JsonObject toJson() {

    JsonObject json =
        new JsonObject()
            .put("sub", getSub())
            .put("organisationId", getOrganisationId())
            .put("authenticatedSub", authenticatedSub)
            .put("authenticatedOrgId", authenticatedOrgId)
            .put("isDelegation", isDelegation())
            .put("isApp", isApp())
            .put("isDirectUser", isDirectUser())
            .put("appId", appId);

    // authorizationRoles
    JsonArray authRolesArr = new JsonArray();
    for (DxRole role : authorizationRoles) {
      authRolesArr.add(role.name());
    }

    // auditRoles
    JsonArray auditRolesArr = new JsonArray();
    for (DxRole role : auditRoles) {
      auditRolesArr.add(role.name());
    }

    // directScopes
    JsonArray scopesArr = new JsonArray();
    for (String scope : directScopes) {
      scopesArr.add(scope);
    }

    json.put("authorizationRoles", authRolesArr);
    json.put("auditRoles", auditRolesArr);
    json.put("directScopes", scopesArr);

    return json;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private String authenticatedSub;
    private String authenticatedOrgId;
    private String delegatorSub;
    private String delegatorOrgId;
    private Set<DxRole> authorizationRoles = Set.of();
    private Set<String> directScopes = Set.of();
    private Set<DxRole> auditRoles = Set.of();
    private String appId;

    public Builder authenticatedSub(String v) {
      this.authenticatedSub = v;
      return this;
    }

    public Builder authenticatedOrgId(String v) {
      this.authenticatedOrgId = v;
      return this;
    }

    public Builder delegatorSub(String v) {
      this.delegatorSub = v;
      return this;
    }

    public Builder delegatorOrgId(String v) {
      this.delegatorOrgId = v;
      return this;
    }

    public Builder authorizationRoles(Set<DxRole> v) {
      this.authorizationRoles = v == null ? Set.of() : v;
      return this;
    }

    public Builder directScopes(Set<String> v) {
      this.directScopes = v == null ? Set.of() : v;
      return this;
    }

    public Builder auditRoles(Set<DxRole> v) {
      this.auditRoles = v == null ? Set.of() : v;
      return this;
    }

    public Builder appId(String v) {
      this.appId = v;
      return this;
    }

    public DxPrincipal build() {
      return new DxPrincipal(this);
    }
  }
}
