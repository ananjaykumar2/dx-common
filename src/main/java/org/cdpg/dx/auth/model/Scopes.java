package org.cdpg.dx.auth.model;

import java.util.Set;

/**
 * The thirteen system scope names. Scopes are the unit of authorization — endpoints require
 * scopes, and a principal's effective scope set is checked against them.
 *
 * <p>Use these constants at route declaration sites rather than bare strings.
 */
public final class Scopes {

  private Scopes() {}

  public static final String DATA_ACCESS = "data-access";
  public static final String OWN_ASSET_MANAGEMENT = "own-asset-management";

  public static final String ORG_USER_MANAGEMENT = "org-user-management";
  public static final String ORG_ASSET_MANAGEMENT = "org-asset-management";
  public static final String ORG_ASSET_PUBLISH = "org-asset-publish";
  public static final String ORG_PUBLISHER_MANAGEMENT = "org-publisher-management";

  public static final String ORG_MANAGEMENT = "org-management";
  public static final String ASSET_PUBLISH = "asset-publish";
  public static final String ASSET_MANAGEMENT = "asset-management";
  public static final String USER_MANAGEMENT = "user-management";
  public static final String PUBLISHER_MANAGEMENT = "publisher-management";
  public static final String ROLE_MANAGEMENT = "role-management";

  public static final String COMPUTE_MANAGEMENT = "compute-management";
  public static final String CREDIT_MANAGEMENT = "credit-management";

  public static final Set<String> ALL =
      Set.of(
          DATA_ACCESS,
          OWN_ASSET_MANAGEMENT,
          ORG_USER_MANAGEMENT,
          ORG_ASSET_MANAGEMENT,
          ORG_ASSET_PUBLISH,
          ORG_PUBLISHER_MANAGEMENT,
          ORG_MANAGEMENT,
          ASSET_PUBLISH,
          ASSET_MANAGEMENT,
          USER_MANAGEMENT,
          PUBLISHER_MANAGEMENT,
          ROLE_MANAGEMENT,
          COMPUTE_MANAGEMENT,
          CREDIT_MANAGEMENT);
}