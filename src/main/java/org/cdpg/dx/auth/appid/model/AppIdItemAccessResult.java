package org.cdpg.dx.auth.appid.model;

import org.cdpg.dx.auth.appid.v1.CheckItemAccessResponse;

/** Immutable result of a successful gRPC CheckItemAccess response. */
public record AppIdItemAccessResult(
    String iid,
    String accessPolicy,
    String resourceServerJson,
    String policiesJson,
    boolean hasOwnerAccess,
    boolean hasAdminAccess) {

  public static AppIdItemAccessResult fromProto(CheckItemAccessResponse resp) {
    return new AppIdItemAccessResult(
        resp.getIid(),
        resp.getAccessPolicy(),
        resp.getResourceServerJson(),
        resp.getPoliciesJson(),
        resp.getHasOwnerAccess(),
        resp.getHasAdminAccess());
  }
}
