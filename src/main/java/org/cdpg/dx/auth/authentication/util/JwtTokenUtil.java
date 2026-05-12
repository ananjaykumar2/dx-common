package org.cdpg.dx.auth.authentication.util;

import io.vertx.core.json.JsonObject;
import java.util.Base64;

public final class JwtTokenUtil {

  private JwtTokenUtil() {}

  public static String extractIssuer(String token) {
    String payload = decodeSegment(token, 1);
    return new JsonObject(payload).getString("iss");
  }

  public static String extractKid(String token) {
    String header = decodeSegment(token, 0);
    return new JsonObject(header).getString("kid");
  }

  private static String decodeSegment(String token, int index) {
    String[] parts = token.split("\\.");
    if (parts.length < 2) throw new IllegalArgumentException("Malformed JWT");
    return new String(Base64.getUrlDecoder().decode(parts[index]));
  }
}