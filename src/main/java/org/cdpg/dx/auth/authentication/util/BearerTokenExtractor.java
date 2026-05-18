package org.cdpg.dx.auth.authentication.util;

import io.vertx.ext.web.RoutingContext;
import org.cdpg.dx.common.config.HttpConstants;

public class BearerTokenExtractor {
  public static String extract(RoutingContext ctx) {
    String auth = ctx.request().getHeader(HttpConstants.HEADER_AUTHORIZATION);
    if (auth != null && auth.startsWith(HttpConstants.BEARER_PREFIX)) {
      return auth.substring(HttpConstants.BEARER_PREFIX.length()).trim();
    }
    return null;
  }
}