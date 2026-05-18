package org.cdpg.dx.common.config;

public final class HttpConstants {

  public static final String HEADER_AUTHORIZATION = "Authorization";
  public static final String HEADER_CONTENT_TYPE  = "Content-Type";
  public static final String HEADER_ORIGIN        = "Origin";

  public static final String BEARER_PREFIX = "Bearer ";
  public static final String BASIC_PREFIX  = "Basic ";

  public static final String APPLICATION_JSON = "application/json";

  public static final String CORS_METHODS = "GET, POST, PUT, DELETE, OPTIONS, PATCH";
  public static final String CORS_HEADERS = "Authorization, Content-Type";


  private HttpConstants() {}
}