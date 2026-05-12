package org.cdpg.dx.auth.authorization.model;

import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

public enum DxScope {
  USER_MANAGEMENT("user-management"),
  ORG_ADMIN_ACCESS("org-admin-access"),
  DATA_ACCESS("data-access"),
  COS_ADMIN_ACCESS("cos-admin-access"),
  COMPUTE_MANAGEMENT("compute-management"),
  CREDIT_MANAGEMENT("credit-management"),
  ASSET_MANAGEMENT("asset-management"),
  WILDCARD("*");

  private final String scope;

  private static final Map<String, DxScope> SCOPE_LOOKUP =
      Arrays.stream(values()).collect(Collectors.toMap(r -> r.scope.toLowerCase(), r -> r));

  DxScope(String scope) {
    this.scope = scope;
  }

  public String getScope() {
    return scope;
  }

  public static DxScope fromString(String scope) {
    return SCOPE_LOOKUP.get(scope.toLowerCase());
  }

  @Override
  public String toString() {
    return scope;
  }
}
