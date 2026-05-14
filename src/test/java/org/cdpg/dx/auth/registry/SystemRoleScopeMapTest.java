package org.cdpg.dx.auth.registry;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;

import org.cdpg.dx.auth.authorization.registry.SystemRoleScopeMap;
import org.cdpg.dx.auth.model.DxRole;
import org.cdpg.dx.auth.model.Scopes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SystemRoleScopeMap Tests")
class SystemRoleScopeMapTest {

  @Test
  @DisplayName("CONSUMER → {data-access}")
  void consumer() {
    assertEquals(Set.of(Scopes.DATA_ACCESS), SystemRoleScopeMap.getScopes(DxRole.CONSUMER));
  }

  @Test
  @DisplayName("PROVIDER → {own-asset-management}")
  void provider() {
    assertEquals(
        Set.of(Scopes.OWN_ASSET_MANAGEMENT), SystemRoleScopeMap.getScopes(DxRole.PROVIDER));
  }

  @Test
  @DisplayName("ORG_ADMIN → five org-level scopes")
  void orgAdmin() {
    assertEquals(
        Set.of(
            Scopes.ORG_USER_MANAGEMENT,
            Scopes.ORG_ASSET_MANAGEMENT,
            Scopes.ORG_ASSET_PUBLISH,
            Scopes.OWN_ASSET_MANAGEMENT,
            Scopes.ORG_PUBLISHER_MANAGEMENT),
        SystemRoleScopeMap.getScopes(DxRole.ORG_ADMIN));
  }

  @Test
  @DisplayName("COS_ADMIN → six platform-level scopes")
  void cosAdmin() {
    assertEquals(
        Set.of(
            Scopes.ORG_MANAGEMENT,
            Scopes.ASSET_PUBLISH,
            Scopes.ASSET_MANAGEMENT,
            Scopes.USER_MANAGEMENT,
            Scopes.PUBLISHER_MANAGEMENT,
            Scopes.ROLE_MANAGEMENT),
        SystemRoleScopeMap.getScopes(DxRole.COS_ADMIN));
  }

  @Test
  @DisplayName("COMPUTE → {compute-management}")
  void compute() {
    assertEquals(Set.of(Scopes.COMPUTE_MANAGEMENT), SystemRoleScopeMap.getScopes(DxRole.COMPUTE));
  }

  @Test
  @DisplayName("returned scope sets are immutable")
  void returnedSetsImmutable() {
    assertThrows(
        UnsupportedOperationException.class,
        () -> SystemRoleScopeMap.getScopes(DxRole.CONSUMER).add("anything"));
  }

  @Test
  @DisplayName("every scope in the map is a valid Scopes.ALL entry")
  void allScopesAreDeclared() {
    for (DxRole role : DxRole.values()) {
      for (String scope : SystemRoleScopeMap.getScopes(role)) {
        assertTrue(
            Scopes.ALL.contains(scope),
            "Role " + role + " references unknown scope: " + scope);
      }
    }
  }
}
