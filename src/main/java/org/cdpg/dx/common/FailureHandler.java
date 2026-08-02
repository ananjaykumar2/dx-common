package org.cdpg.dx.common;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.common.config.HttpConstants;
import org.cdpg.dx.common.exception.DxInternalServerErrorException;
import org.cdpg.dx.common.exception.DxTimeOutException;
import org.cdpg.dx.common.response.DxErrorResponse;
import org.cdpg.dx.common.response.DxErrorResponseNGSILD;
import org.cdpg.dx.common.util.ExceptionHttpStatusMapper;
import org.cdpg.dx.common.util.RequestValidationErrorFormatter;
import org.cdpg.dx.common.util.SchemaBranchResolver;
import org.cdpg.dx.common.util.ThrowableUtils;

public class FailureHandler implements Handler<RoutingContext> {

  private static final Logger LOGGER = LogManager.getLogger(FailureHandler.class);
  private static final String HEADER_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
  private static final String HEADER_HOST = "Host";
  private static final String HEADER_ALLOW_METHODS = "Access-Control-Allow-Methods";
  private static final String HEADER_ALLOW_HEADERS = "Access-Control-Allow-Headers";

  private final URNGenerator urnGenerator;
  private final String ngsildPathPattern;
  private final SchemaBranchResolver branchResolver;

  /**
   * Create a FailureHandler with configurable NGSI-LD path pattern.
   *
   * @param urnGenerator the URN generator for error responses
   * @param ngsildPathPattern regex pattern for NGSI-LD paths (e.g. "/ngsi-ld/v1.*" or
   *     ".*iudx/v2/subscriptions.*"). Null means no NGSI-LD path matching.
   * @param branchResolver resolves the branches of a failed {@code oneOf} so validation errors can
   *     name the offending field instead of only saying that nothing matched. Null disables that,
   *     which is the right default anywhere the schema router is not available.
   */
  public FailureHandler(
      URNGenerator urnGenerator, String ngsildPathPattern, SchemaBranchResolver branchResolver) {
    this.urnGenerator = urnGenerator;
    this.ngsildPathPattern = ngsildPathPattern;
    this.branchResolver = branchResolver;
  }

  public FailureHandler(URNGenerator urnGenerator, String ngsildPathPattern) {
    this(urnGenerator, ngsildPathPattern, null);
  }

  public FailureHandler(URNGenerator urnGenerator) {
    this(urnGenerator, null, null);
  }

  /**
   * Request validation failures are caller mistakes, not server faults: log one readable line at
   * warn and keep the (very long) vertx-validation stack trace behind debug.
   */
  private void logValidationFailure(RoutingContext context, Throwable failure) {
    LOGGER.warn(
        "Request validation failed [{} {}]: {}",
        context.request().method(),
        context.request().path(),
        RequestValidationErrorFormatter.logDetail(failure, branchResolver));
    LOGGER.debug("Request validation failure stack trace", failure);
  }

  @Override
  public void handle(RoutingContext context) {
    String path = context.request().path();
    LOGGER.debug("path : {} ", path);

    if (ngsildPathPattern != null && path.matches(ngsildPathPattern)) {
      ngsildErrorResponse(context);
    } else {
      nonNgsildErrorResponse(context);
    }
  }

  private void nonNgsildErrorResponse(RoutingContext context) {
    Throwable failure = context.failure();
    if (failure == null) {
      LOGGER.warn(
          "FailureHandler triggered without an actual Throwable. Possibly context.fail(statusCode) was used.");
      int status = context.statusCode();
      if (status == 408) {
        failure = new DxTimeOutException("Request timed out");
      } else {
        failure = new DxInternalServerErrorException("Unknown server error");
      }
    }
    LOGGER.debug("FailureHandler: {}", failure.getClass());

    if (RequestValidationErrorFormatter.isValidationFailure(failure)) {
      logValidationFailure(context, failure);
      context
          .response()
          .putHeader(HttpConstants.HEADER_CONTENT_TYPE, HttpConstants.APPLICATION_JSON)
          .putHeader(HEADER_ALLOW_ORIGIN, "*")
          .putHeader(HEADER_ALLOW_METHODS, HttpConstants.CORS_METHODS)
          .putHeader(HEADER_ALLOW_HEADERS, HttpConstants.CORS_HEADERS)
          .setStatusCode(400)
          .end(
              ResponseUtil.generateResponse(
                      HttpStatusCode.BAD_REQUEST,
                      urnGenerator.generateUrn(HttpStatusCode.BAD_REQUEST.getPath()),
                      RequestValidationErrorFormatter.clientMessage(failure, branchResolver))
                  .toString());
      return;
    }

    HttpStatusCode statusCode = ExceptionHttpStatusMapper.map(failure);
    LOGGER.debug("FailureHandler() statusCode: {}", statusCode.getValue());
    LOGGER.error("Error: {}", failure.getMessage(), failure);

    String safeDetail =
        ThrowableUtils.isSafeToExpose(failure)
            ? failure.getMessage()
            : "An unexpected error occurred";

    String urn = urnGenerator.generateUrn(statusCode.getPath());

    DxErrorResponse errorResponse =
        new DxErrorResponse(urn, statusCode.getDescription(), safeDetail);

    if (!context.response().ended()) {
      int status = statusCode.getValue();
      if (status < 400 || status > 599) {
        status = 500;
      }

      context
          .response()
          .putHeader(HttpConstants.HEADER_CONTENT_TYPE, HttpConstants.APPLICATION_JSON)
          .putHeader(HEADER_ALLOW_ORIGIN, "*")
          .putHeader(HEADER_ALLOW_METHODS, HttpConstants.CORS_METHODS)
          .putHeader(HEADER_ALLOW_HEADERS, HttpConstants.CORS_HEADERS)
          .setStatusCode(status)
          .end(errorResponse.toJson().encode());
    }
  }

  private void ngsildErrorResponse(RoutingContext context) {
    Throwable failure = context.failure();
    String instance = context.request().getHeader(HEADER_HOST);
    if (failure == null) {
      LOGGER.warn(
          "FailureHandlerNGSILD triggered without an actual Throwable. Possibly context.fail(statusCode) was used.");
      int status = context.statusCode();
      if (status == 408) {
        failure = new DxTimeOutException("Request timed out");
      } else {
        failure = new DxInternalServerErrorException("Unknown server error");
      }
    }
    LOGGER.debug("FailureHandlerNGSILD: {}", failure.getClass());

    if (RequestValidationErrorFormatter.isValidationFailure(failure)) {
      logValidationFailure(context, failure);
      context
          .response()
          .putHeader(HttpConstants.HEADER_CONTENT_TYPE, HttpConstants.APPLICATION_JSON)
          .putHeader(HEADER_ALLOW_ORIGIN, "*")
          .putHeader(HEADER_ALLOW_METHODS, HttpConstants.CORS_METHODS)
          .putHeader(HEADER_ALLOW_HEADERS, HttpConstants.CORS_HEADERS)
          .setStatusCode(400)
          .end(
              ResponseUtilNGSILD.generateResponse(
                      HttpStatusCode.BAD_REQUEST,
                      urnGenerator.generateUrn(HttpStatusCode.BAD_REQUEST.getPath()),
                      RequestValidationErrorFormatter.clientMessage(failure, branchResolver),
                      instance)
                  .toString());
      return;
    }

    HttpStatusCode statusCode = ExceptionHttpStatusMapper.map(failure);
    LOGGER.debug("FailureHandlerNGSILD() statusCode: {}", statusCode.getValue());
    LOGGER.error("error: {}", failure.getMessage(), failure);

    String safeDetail =
        ThrowableUtils.isSafeToExpose(failure)
            ? failure.getMessage()
            : "An unexpected error occurred";

    String urn = urnGenerator.generateUrn(statusCode.getPath());

    DxErrorResponseNGSILD errorResponse =
        new DxErrorResponseNGSILD(urn, statusCode.getDescription(), safeDetail, instance);

    if (!context.response().ended()) {
      int status = statusCode.getValue();
      if (status < 400 || status > 599) {
        status = 500;
      }

      context
          .response()
          .putHeader(HttpConstants.HEADER_CONTENT_TYPE, HttpConstants.APPLICATION_JSON)
          .putHeader(HEADER_ALLOW_ORIGIN, "*")
          .putHeader(HEADER_ALLOW_METHODS, HttpConstants.CORS_METHODS)
          .putHeader(HEADER_ALLOW_HEADERS, HttpConstants.CORS_HEADERS)
          .setStatusCode(status)
          .end(errorResponse.toJson().encode());
    }
  }
}
