package org.cdpg.dx.common.response;

import static org.cdpg.dx.common.config.CorsUtil.HEADER_ALLOW_ORIGIN;
import static org.cdpg.dx.common.config.CorsUtil.allowedOrigins;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.cdpg.dx.common.HttpStatusCode;
import org.cdpg.dx.common.URNGenerator;
import org.cdpg.dx.common.util.PaginationInfo;

/**
 * Generic response builder for standardized API responses across all DX microservices.
 *
 * <p>Provides static helper methods to:
 * <ul>
 *   <li>Create {@link DxResponse} objects for service-layer results</li>
 *   <li>Send JSON responses directly via {@link RoutingContext} with proper CORS headers</li>
 * </ul>
 *
 * <h3>Usage in controllers:</h3>
 * <pre>{@code
 * // Send success with result
 * ResponseBuilder.sendSuccess(ctx, result, urnGenerator);
 *
 * // Send success with pagination
 * ResponseBuilder.sendSuccess(ctx, result, pageInfo, urnGenerator);
 *
 * // Send created
 * ResponseBuilder.sendCreated(ctx, "Resource created", result, urnGenerator);
 *
 * // Build response object (for service layer)
 * DxResponse<MyResult> response = ResponseBuilder.success(urnGenerator, "detail", result);
 * }</pre>
 */
public class ResponseBuilder {

  private ResponseBuilder() {}

  // --- Build DxResponse objects (for service-layer use) ---

  public static <T> DxResponse<T> success(
      URNGenerator urnGenerator, String detail, T result, PaginationInfo pageInfo) {
    HttpStatusCode code = HttpStatusCode.SUCCESS;
    String urn = urnGenerator.generateUrn(code.getPath());
    return new DxResponse<>(urn, code.getDescription(), detail, result, pageInfo);
  }

  public static <T> DxResponse<T> success(URNGenerator urnGenerator, String detail, T result) {
    HttpStatusCode code = HttpStatusCode.SUCCESS;
    String urn = urnGenerator.generateUrn(code.getPath());
    return new DxResponse<>(urn, code.getDescription(), detail, result, null);
  }

  public static DxResponse<Void> success(URNGenerator urnGenerator, String detail) {
    return success(urnGenerator, detail, null);
  }

  // --- Send responses via RoutingContext ---

  public static <T> void send(
      RoutingContext ctx,
      HttpStatusCode status,
      String detail,
      T result,
      PaginationInfo pageInfo,
      URNGenerator urnGenerator) {
    if (status == HttpStatusCode.NO_CONTENT) {
      ctx.response().setStatusCode(status.getValue()).end();
      return;
    }
    String urn = urnGenerator.generateUrn(status.getPath());
    DxResponse<T> response =
        new DxResponse<>(urn, status.getDescription(), detail, result, pageInfo);
    String requestOrigin = ctx.request().getHeader("Origin");
    if (allowedOrigins != null
        && requestOrigin != null
        && (allowedOrigins.contains(requestOrigin) || allowedOrigins.contains("*"))) {
      ctx.response()
          .putHeader("Content-Type", "application/json")
          .putHeader(HEADER_ALLOW_ORIGIN, requestOrigin)
          .putHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
          .putHeader("Access-Control-Allow-Headers", "Authorization, Content-Type")
          .setStatusCode(status.getValue())
          .end(JsonObject.mapFrom(response).encode());
    } else {
      ctx.response()
          .putHeader("Content-Type", "application/json")
          .setStatusCode(status.getValue())
          .end(JsonObject.mapFrom(response).encode());
    }
  }

  // --- Success shortcuts ---

  public static void sendSuccess(RoutingContext ctx, String detail, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, detail, null, null, urnGenerator);
  }

  public static <R> void sendSuccess(RoutingContext ctx, R result, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, null, result, null, urnGenerator);
  }

  public static <T> void sendSuccess(
      RoutingContext ctx, T result, PaginationInfo pageInfo, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, null, result, pageInfo, urnGenerator);
  }

  public static <T> void sendSuccess(
      RoutingContext ctx,
      String detail,
      T result,
      PaginationInfo pageInfo,
      URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, detail, result, pageInfo, urnGenerator);
  }

  public static <T> void sendSuccess(
      RoutingContext ctx, String detail, T result, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.SUCCESS, detail, result, null, urnGenerator);
  }

  // --- Created shortcuts ---

  public static <T> void sendCreated(
      RoutingContext ctx, String detail, T result, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.CREATED, detail, result, null, urnGenerator);
  }

  public static void sendCreated(RoutingContext ctx, String detail, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.CREATED, detail, null, null, urnGenerator);
  }

  // --- Other status shortcuts ---

  public static void sendNoContent(RoutingContext ctx, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.NO_CONTENT, null, null, null, urnGenerator);
  }

  public static void sendProcessing(RoutingContext ctx, String detail, URNGenerator urnGenerator) {
    send(ctx, HttpStatusCode.PROCESSING, detail, null, null, urnGenerator);
  }

  public static void sendForbiddenNoAccess(RoutingContext ctx, String detail, URNGenerator urnGenerator) {

    send(ctx, HttpStatusCode.FORBIDDEN_NO_ACCESS, detail, null, null, urnGenerator);
  }

  public static <T> void sendForbiddenAccessPending(RoutingContext ctx, String detail, T result,
      URNGenerator urnGenerator) {

    send(ctx, HttpStatusCode.FORBIDDEN_ACCESS_PENDING, detail, result, null, urnGenerator);
  }

  public static <T> void sendForbiddenAccessRejected(RoutingContext ctx, String detail,
                                                     URNGenerator urnGenerator) {

    send(ctx,
        HttpStatusCode.FORBIDDEN_ACCESS_REJECTED, detail, null, null, urnGenerator);
  }

  // --- Error shortcuts ---

  public static void sendError(
      RoutingContext ctx, HttpStatusCode status, URNGenerator urnGenerator) {
    send(ctx, status, status.getDescription(), null, null, urnGenerator);
  }

  public static void sendError(
      RoutingContext ctx, HttpStatusCode status, String detail, URNGenerator urnGenerator) {
    send(ctx, status, detail, null, null, urnGenerator);
  }
}
