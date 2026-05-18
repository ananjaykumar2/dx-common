package org.cdpg.dx.auth.authentication.util;

import io.vertx.core.json.JsonObject;
import java.util.Base64;
import org.cdpg.dx.auth.common.AuthConstants;
import org.cdpg.dx.keycloak.config.KeycloakConstants;

public final class JwtTokenUtil {

  private JwtTokenUtil() {}

  public static String extractIssuer(String token) {
    String payload = decodeSegment(token, 1);
    return new JsonObject(payload).getString(KeycloakConstants.CLAIM_ISS);
  }

  public static String extractKid(String token) {
    String header = decodeSegment(token, 0);
    return new JsonObject(header).getString(KeycloakConstants.CLAIM_KID);
  }

  private static String decodeSegment(String token, int index) {
    String[] parts = token.split("\\.");
    if (parts.length < 2) throw new IllegalArgumentException(AuthConstants.MALFORMED_JWT);
    return new String(Base64.getUrlDecoder().decode(parts[index]));
  }
}
