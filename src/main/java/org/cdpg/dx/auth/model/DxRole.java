package org.cdpg.dx.auth.model;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/** Immutable system roles configured in Keycloak and authoritative in code. */
public enum DxRole {
  CONSUMER("consumer"),
  PROVIDER("provider"),
  ORG_ADMIN("org_admin"),
  COS_ADMIN("cos_admin"),
  COMPUTE("compute");

  /** Canonical Keycloak role name. */
  private final String value;

  /** Case-insensitive role lookup map. */
  private static final Map<String, DxRole> LOOKUP =
      Arrays.stream(values())
          .collect(
              Collectors.toUnmodifiableMap(
                  role -> role.value.toLowerCase(Locale.ROOT), role -> role));

  DxRole(String value) {
    this.value = value;
  }

  public String value() {
    return value;
  }

  public static Optional<DxRole> fromString(String role) {
    if (role == null || role.isBlank()) return Optional.empty();
    return Optional.ofNullable(LOOKUP.get(role.toLowerCase(Locale.ROOT)));
  }
}
