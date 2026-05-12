package org.cdpg.dx.auth.v2.model;

import static org.junit.jupiter.api.Assertions.*;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("DxPrincipal Tests")
class DxPrincipalTest {

  @Nested
  @DisplayName("Plain user")
  class PlainUser {

    @Test
    @DisplayName("effective getters return authenticated identity")
    void effectiveGettersReturnAuthenticated() {
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("alice")
              .authenticatedOrgId("org-a")
              .authorizationRoles(Set.of(DxRole.ORG_ADMIN))
              .auditRoles(Set.of(DxRole.ORG_ADMIN))
              .build();

      assertEquals("alice", p.getSub());
      assertEquals("org-a", p.getOrganisationId());
      assertEquals("alice", p.getAuthenticatedSub());
      assertEquals("org-a", p.getAuthenticatedOrgId());
      assertTrue(p.isDirectUser());
      assertFalse(p.isDelegation());
      assertFalse(p.isApp());
      assertNull(p.getAppId());
    }
  }

  @Nested
  @DisplayName("Delegation")
  class Delegation {

    @Test
    @DisplayName("getSub/getOrganisationId return delegator, raw getters return delegatee")
    void effectiveSwitchesToDelegator() {
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("bob")
              .authenticatedOrgId("org-b")
              .delegatorSub("alice")
              .delegatorOrgId("org-a")
              .directScopes(Set.of(Scopes.DATA_ACCESS))
              .auditRoles(Set.of(DxRole.ORG_ADMIN))
              .build();

      assertEquals("alice", p.getSub());
      assertEquals("org-a", p.getOrganisationId());
      assertEquals("bob", p.getAuthenticatedSub());
      assertEquals("org-b", p.getAuthenticatedOrgId());
      assertTrue(p.isDelegation());
      assertFalse(p.isDirectUser());
      assertFalse(p.isApp());
    }

    @Test
    @DisplayName("authorizationRoles must be empty on delegation principal (by convention)")
    void authorizationRolesEmpty() {
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("bob")
              .authenticatedOrgId("org-b")
              .delegatorSub("alice")
              .delegatorOrgId("org-a")
              .authorizationRoles(Set.of())
              .directScopes(Set.of(Scopes.DATA_ACCESS))
              .build();
      assertTrue(p.getAuthorizationRoles().isEmpty());
    }

    @Test
    @DisplayName("rejects delegator sub without delegator orgId (and vice versa)")
    void delegatorMustBeBoth() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              DxPrincipal.builder()
                  .authenticatedSub("bob")
                  .authenticatedOrgId("org-b")
                  .delegatorSub("alice")
                  .build());

      assertThrows(
          IllegalArgumentException.class,
          () ->
              DxPrincipal.builder()
                  .authenticatedSub("bob")
                  .authenticatedOrgId("org-b")
                  .delegatorOrgId("org-a")
                  .build());
    }
  }

  @Nested
  @DisplayName("App credentials")
  class AppCreds {

    @Test
    @DisplayName("acts as owner — sub and org are the owner's")
    void appActsAsOwner() {
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("ananjay")
              .authenticatedOrgId("org-a")
              .directScopes(Set.of(Scopes.OWN_ASSET_MANAGEMENT))
              .auditRoles(Set.of(DxRole.PROVIDER))
              .appId("analytics-worker")
              .build();

      assertEquals("ananjay", p.getSub());
      assertEquals("org-a", p.getOrganisationId());
      assertEquals("analytics-worker", p.getAppId());
      assertTrue(p.isApp());
      assertFalse(p.isDelegation());
      assertFalse(p.isDirectUser());
    }
  }

  @Nested
  @DisplayName("Invariants")
  class Invariants {

    @Test
    @DisplayName("rejects principal that is both delegation and app")
    void delegationAndAppAreMutuallyExclusive() {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              DxPrincipal.builder()
                  .authenticatedSub("bob")
                  .authenticatedOrgId("org-b")
                  .delegatorSub("alice")
                  .delegatorOrgId("org-a")
                  .appId("some-app")
                  .build());
    }

    @Test
    @DisplayName("allows null authenticatedOrgId (orgId is optional)")
    void allowsNullAuthenticatedOrgId() {
      DxPrincipal p = DxPrincipal.builder().authenticatedSub("alice").build();
      assertEquals("alice", p.getSub());
      assertNull(p.getOrganisationId());
    }
  }

  @Nested
  @DisplayName("Defensive copy")
  class DefensiveCopy {

    @Test
    @DisplayName("caller cannot mutate authorizationRoles after build")
    void authorizationRolesImmutable() {
      Set<DxRole> mutable = new HashSet<>();
      mutable.add(DxRole.CONSUMER);
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("a")
              .authenticatedOrgId("o")
              .authorizationRoles(mutable)
              .build();
      mutable.add(DxRole.COS_ADMIN);

      assertEquals(Set.of(DxRole.CONSUMER), p.getAuthorizationRoles());
      assertThrows(
          UnsupportedOperationException.class,
          () -> p.getAuthorizationRoles().add(DxRole.PROVIDER));
    }

    @Test
    @DisplayName("caller cannot mutate directScopes after build")
    void directScopesImmutable() {
      Set<String> mutable = new HashSet<>();
      mutable.add(Scopes.DATA_ACCESS);
      DxPrincipal p =
          DxPrincipal.builder()
              .authenticatedSub("a")
              .authenticatedOrgId("o")
              .directScopes(mutable)
              .build();
      mutable.add(Scopes.ORG_MANAGEMENT);

      assertEquals(Set.of(Scopes.DATA_ACCESS), p.getDirectScopes());
      assertThrows(
          UnsupportedOperationException.class, () -> p.getDirectScopes().add(Scopes.ASSET_PUBLISH));
    }
  }
}
