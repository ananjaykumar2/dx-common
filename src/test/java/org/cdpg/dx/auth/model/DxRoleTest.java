package org.cdpg.dx.auth.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("DxRole Tests")
class DxRoleTest {

  @Nested
  @DisplayName("fromKeycloakName")
  class FromKeycloakName {

    @Test
    @DisplayName("resolves each of the five system roles")
    void resolvesAllFiveRoles() {
      assertEquals(Optional.of(DxRole.CONSUMER), DxRole.fromString("consumer"));
      assertEquals(Optional.of(DxRole.PROVIDER), DxRole.fromString("provider"));
      assertEquals(Optional.of(DxRole.ORG_ADMIN), DxRole.fromString("org_admin"));
      assertEquals(Optional.of(DxRole.COS_ADMIN), DxRole.fromString("cos_admin"));
      assertEquals(Optional.of(DxRole.COMPUTE), DxRole.fromString("compute"));
    }

    @Test
    @DisplayName("is case-insensitive")
    void caseInsensitive() {
      assertEquals(Optional.of(DxRole.ORG_ADMIN), DxRole.fromString("ORG_ADMIN"));
      assertEquals(Optional.of(DxRole.COS_ADMIN), DxRole.fromString("Cos_Admin"));
    }

    @Test
    @DisplayName("returns empty for unknown names")
    void unknownReturnsEmpty() {
      assertEquals(Optional.empty(), DxRole.fromString("delegate"));
      assertEquals(Optional.empty(), DxRole.fromString("admin"));
      assertEquals(Optional.empty(), DxRole.fromString(""));
    }

    @Test
    @DisplayName("returns empty for null")
    void nullReturnsEmpty() {
      assertEquals(Optional.empty(), DxRole.fromString(null));
    }
  }

  @Nested
  @DisplayName("keycloakName")
  class KeycloakName {

    @Test
    @DisplayName("round-trips through fromKeycloakName")
    void roundTrip() {
      for (DxRole role : DxRole.values()) {
        assertEquals(
            Optional.of(role),
            DxRole.fromString(role.value()),
            "round-trip failed for " + role);
      }
    }
  }

  @Test
  @DisplayName("has exactly five values — design contract")
  void fiveRolesExactly() {
    assertEquals(5, DxRole.values().length);
  }
}