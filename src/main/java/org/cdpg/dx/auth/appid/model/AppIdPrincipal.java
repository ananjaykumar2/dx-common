package org.cdpg.dx.auth.appid.model;

import java.util.List;
import org.cdpg.dx.auth.appid.v1.AppIdPrincipalProto;

/** Immutable identity principal from a successful gRPC VerifyAppId response. */
public record AppIdPrincipal(
    String appId,
    String userId,
    String organisationId,
    List<String> roles,
    List<String> scopes,
    long expiresAtEpoch) {

  public static AppIdPrincipal fromProto(AppIdPrincipalProto proto) {
    return new AppIdPrincipal(
        proto.getAppId(),
        proto.getUserId(),
        proto.getOrganisationId(),
        proto.getRolesList(),
        proto.getScopesList(),
        proto.getExpiresAtEpoch());
  }
}
