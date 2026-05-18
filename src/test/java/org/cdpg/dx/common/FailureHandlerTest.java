package org.cdpg.dx.common;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;
import org.cdpg.dx.common.exception.DxBadRequestException;
import org.cdpg.dx.common.exception.DxNotFoundException;
import org.cdpg.dx.common.exception.DxInternalServerErrorException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

@DisplayName("FailureHandler Tests")
class FailureHandlerTest {

  private FailureHandler handler;
  private RoutingContext ctx;
  private HttpServerResponse response;
  private HttpServerRequest request;

  @BeforeEach
  void setUp() {
    handler = new FailureHandler(new URNGenerator("urn:dx:test:"));
    ctx = mock(RoutingContext.class);
    response = mock(HttpServerResponse.class);
    request = mock(HttpServerRequest.class);
    when(ctx.response()).thenReturn(response);
    when(ctx.request()).thenReturn(request);
    when(request.path()).thenReturn("/api/test");
    when(response.putHeader(anyString(), anyString())).thenReturn(response);
    when(response.setStatusCode(anyInt())).thenReturn(response);
    when(response.ended()).thenReturn(false);
  }

  @Nested
  @DisplayName("Non-NGSILD error handling")
  class NonNgsildTests {

    @Test
    @DisplayName("DxBadRequestException should return 400")
    void badRequestReturns400() {
      when(ctx.failure()).thenReturn(new DxBadRequestException("bad input"));
      handler.handle(ctx);
      verify(response).setStatusCode(400);
      verify(response).end(anyString());
    }

    @Test
    @DisplayName("DxNotFoundException should return 404")
    void notFoundReturns404() {
      when(ctx.failure()).thenReturn(new DxNotFoundException("not found"));
      handler.handle(ctx);
      verify(response).setStatusCode(404);
    }

    @Test
    @DisplayName("DxInternalServerErrorException should return 500")
    void internalServerErrorReturns500() {
      when(ctx.failure()).thenReturn(new DxInternalServerErrorException("server error"));
      handler.handle(ctx);
      verify(response).setStatusCode(500);
    }

    @Test
    @DisplayName("null failure with status 408 should be treated as timeout")
    void nullFailureTimeout() {
      when(ctx.failure()).thenReturn(null);
      when(ctx.statusCode()).thenReturn(408);
      handler.handle(ctx);
      verify(response).setStatusCode(408);
    }

    @Test
    @DisplayName("null failure with non-408 status should return 500")
    void nullFailureDefault() {
      when(ctx.failure()).thenReturn(null);
      when(ctx.statusCode()).thenReturn(0);
      handler.handle(ctx);
      verify(response).setStatusCode(500);
    }

    @Test
    @DisplayName("should set CORS headers")
    void setsCorsHeaders() {
      when(ctx.failure()).thenReturn(new DxBadRequestException("test"));
      handler.handle(ctx);
      verify(response).putHeader("Access-Control-Allow-Origin", "*");
      verify(response).putHeader("Content-Type", "application/json");
    }

    @Test
    @DisplayName("should not write if response already ended")
    void alreadyEnded() {
      when(ctx.failure()).thenReturn(new DxBadRequestException("test"));
      when(response.ended()).thenReturn(true);
      handler.handle(ctx);
      verify(response, never()).end(anyString());
    }

    @Test
    @DisplayName("non-BaseDxException message should not be exposed")
    void unsafeMessageHidden() {
      when(ctx.failure()).thenReturn(new RuntimeException("secret internal error"));
      handler.handle(ctx);
      verify(response).setStatusCode(500);
      verify(response).end(argThat((org.mockito.ArgumentMatcher<String>) s -> s.contains("An unexpected error occurred")));
    }
  }

  @Nested
  @DisplayName("NGSILD path routing")
  class NgsildRoutingTests {

    @Test
    @DisplayName("should route NGSILD paths to NGSILD handler")
    void routesNgsild() {
      FailureHandler ngsildHandler = new FailureHandler(new URNGenerator("urn:dx:rs:"), "/ngsi-ld/.*");
      when(request.path()).thenReturn("/ngsi-ld/v1/entities");
      when(request.getHeader("Host")).thenReturn("localhost:8443");
      when(ctx.failure()).thenReturn(new DxNotFoundException("entity not found"));
      ngsildHandler.handle(ctx);
      verify(response).setStatusCode(404);
    }
  }
}
