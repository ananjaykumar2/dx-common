package org.cdpg.dx.common.util;

import static org.junit.jupiter.api.Assertions.*;

import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.pointer.JsonPointer;
import io.vertx.ext.web.validation.BodyProcessorException;
import io.vertx.ext.web.validation.MalformedValueException;
import io.vertx.ext.web.validation.ParameterProcessorException;
import io.vertx.ext.web.validation.RequestPredicateException;
import io.vertx.ext.web.validation.impl.ParameterLocation;
import io.vertx.json.schema.ValidationException;
import io.vertx.json.schema.common.ValidationExceptionImpl;
import org.cdpg.dx.common.exception.DxBadRequestException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RequestValidationErrorFormatter Tests")
class RequestValidationErrorFormatterTest {

  private static ValidationException schemaFailure(String message, String keyword, String scope) {
    ValidationExceptionImpl failure =
        (ValidationExceptionImpl) ValidationException.create(message, keyword, new JsonObject());
    failure.setInputScope(JsonPointer.from(scope));
    return failure;
  }

  @Test
  @DisplayName("Only request validation failures are recognised")
  void recognisesValidationFailures() {
    assertTrue(
        RequestValidationErrorFormatter.isValidationFailure(
            new RequestPredicateException("body required")));
    assertFalse(
        RequestValidationErrorFormatter.isValidationFailure(new DxBadRequestException("nope")));
  }

  @Test
  @DisplayName("Missing required parameter names the parameter and its location")
  void missingParameter() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            ParameterProcessorException.createMissingParameterWhenRequired(
                "resourceId", ParameterLocation.QUERY));

    assertEquals("Missing required query parameter 'resourceId'", message);
  }

  @Test
  @DisplayName("Parameter parsing error reports the root cause")
  void parameterParsingError() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            ParameterProcessorException.createParsingError(
                "limit", ParameterLocation.QUERY, new MalformedValueException("not a number")));

    assertEquals("Malformed query parameter 'limit': not a number", message);
  }

  @Test
  @DisplayName("Jackson's source footer is trimmed but the line and column survive")
  void jacksonParseErrorIsCondensed() {
    String jacksonMessage =
        "Unexpected character ('{' (code 123)): was expecting double-quote to start field name\n"
            + " at [Source: REDACTED (`StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION` disabled);"
            + " line: 30, column: 6]";

    String message =
        RequestValidationErrorFormatter.clientMessage(
            BodyProcessorException.createParsingError(
                "application/json", new DecodeException(jacksonMessage)));

    assertEquals("Request body is not valid JSON (line 30, column 6)", message);
    assertFalse(message.contains("\n"));
    assertFalse(message.contains("REDACTED"));
    assertFalse(message.contains("double-quote"), "parser internals must not reach the caller");
  }

  @Test
  @DisplayName("A parse error without a source footer is passed through untouched")
  void parseErrorWithoutFooter() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            BodyProcessorException.createParsingError(
                "application/json", new DecodeException("Unexpected end-of-input")));

    assertEquals("Request body is not valid JSON", message);
  }

  @Test
  @DisplayName("Parameter validation error is neither called a body nor a regex dump")
  void parameterValidationErrorIsNotCalledABody() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            ParameterProcessorException.createValidationError(
                "id",
                ParameterLocation.QUERY,
                ValidationException.create(
                    "provided string should respect pattern ^[a-z]+$", "pattern", "NOPE")));

    assertEquals("Invalid query parameter 'id': does not match the required format", message);
  }

  @Test
  @DisplayName("The regex is kept out of the response but survives in the log line")
  void patternIsLoggedNotReturned() {
    Throwable failure =
        ParameterProcessorException.createValidationError(
            "id",
            ParameterLocation.QUERY,
            ValidationException.create(
                "provided string should respect pattern ^[a-z]+$", "pattern", "NOPE"));

    assertFalse(RequestValidationErrorFormatter.clientMessage(failure).contains("^[a-z]+$"));
    assertTrue(
        RequestValidationErrorFormatter.logDetail(failure)
            .contains("[constraint=provided string should respect pattern ^[a-z]+$]"));
  }

  @Test
  @DisplayName("Body validation error points at the failing field instead of dumping the wrapper")
  void bodyValidationErrorNamesField() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            BodyProcessorException.createValidationError(
                "application/json",
                schemaFailure("provided string should have size >= 3", "minLength", "/items/0/name")));

    assertEquals(
        "Invalid request body at 'items[0].name': provided string should have size >= 3",
        message);
  }

  @Test
  @DisplayName("Missing property is reported as a missing property, not a schema dump")
  void bodyMissingProperty() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            BodyProcessorException.createValidationError(
                "application/json",
                schemaFailure("provided object should contain property email", "required", "/user")));

    assertEquals(
        "Invalid request body at 'user': missing required property 'email'", message);
  }

  @Test
  @DisplayName("oneOf failure at the document root gets a readable message")
  void oneOfAtRoot() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            BodyProcessorException.createValidationError(
                "application/json", ValidationException.create("No schema matches", "oneOf", null)));

    assertEquals(
        "Invalid request body: does not match any of the shapes allowed by the API specification",
        message);
  }

  @Test
  @DisplayName("The async path's arbitrary branch cause is ignored, so every request answers alike")
  void oneOfIsDeterministicAcrossSyncAndAsyncPaths() {
    // What validateSync throws: no cause at all.
    Throwable afterWarmup =
        BodyProcessorException.createValidationError(
            "application/json", ValidationException.create("No schema matches", "oneOf", null));

    // What validateAsync throws: whichever branch future finished last, wrapped as the cause.
    Throwable firstRequest =
        BodyProcessorException.createValidationError(
            "application/json",
            ValidationException.create(
                "No schema matches",
                "oneOf",
                null,
                new IllegalStateException(
                    ValidationException.create(
                        "provided object should contain property name", "required", null))));

    assertEquals(
        RequestValidationErrorFormatter.clientMessage(afterWarmup),
        RequestValidationErrorFormatter.clientMessage(firstRequest));
    assertFalse(RequestValidationErrorFormatter.clientMessage(firstRequest).contains("name"));
  }

  @Test
  @DisplayName("oneOf matching too many shapes is not reported as matching none")
  void oneOfMatchingMoreThanOne() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            BodyProcessorException.createValidationError(
                "application/json",
                ValidationException.create("More than one schema valid", "oneOf", null)));

    assertEquals(
        "Invalid request body: matches more than one of the shapes allowed by the API"
            + " specification",
        message);
  }

  @Test
  @DisplayName("Unsupported content type is reported without a schema lookup")
  void unsupportedContentType() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            BodyProcessorException.createMissingMatchingBodyProcessor("text/plain"));

    assertEquals("Unsupported request body content type 'text/plain'", message);
  }

  @Test
  @DisplayName("Request predicate message drops the [Bad Request] prefix")
  void predicateMessageIsStripped() {
    String message =
        RequestValidationErrorFormatter.clientMessage(
            new RequestPredicateException("Body required"));

    assertEquals("Body required", message);
  }

  @Test
  @DisplayName("Log detail carries the keyword the client message hides")
  void logDetailCarriesKeyword() {
    String detail =
        RequestValidationErrorFormatter.logDetail(
            BodyProcessorException.createValidationError(
                "application/json",
                schemaFailure("No schema matches", "oneOf", "/subscription")));

    assertTrue(detail.contains("at 'subscription'"), detail);
    assertTrue(detail.contains("[keyword=oneOf]"), detail);
  }

  @Test
  @DisplayName("Unknown failures fall back to a generic message")
  void unknownFailureFallsBack() {
    assertEquals(
        "Request does not match the API specification",
        RequestValidationErrorFormatter.clientMessage(new IllegalStateException("boom")));
  }

  // ---------------------------------------------------------------------
  // oneOf branch expansion
  // ---------------------------------------------------------------------

  /** Minimal Schema stub: only getJson/validateSync matter to the formatter. */
  private static final class StubSchema implements io.vertx.json.schema.Schema {
    private final JsonObject json;
    private final ValidationException failure;

    StubSchema(String title, ValidationException failure) {
      this(title == null ? new JsonObject() : new JsonObject().put("title", title), failure);
    }

    StubSchema(JsonObject json, ValidationException failure) {
      this.json = json;
      this.failure = failure;
    }

    @Override
    public io.vertx.core.Future<Void> validateAsync(Object in) {
      return failure == null ? io.vertx.core.Future.succeededFuture() : io.vertx.core.Future.failedFuture(failure);
    }

    @Override
    public void validateSync(Object in) {
      if (failure != null) {
        throw failure;
      }
    }

    @Override
    public JsonPointer getScope() {
      return JsonPointer.create();
    }

    @Override
    public Object getJson() {
      return json;
    }

    @Override
    public boolean isSync() {
      return true;
    }
  }

  private static BodyProcessorException oneOfOver(int branches) {
    JsonObject schemaJson = new JsonObject();
    io.vertx.core.json.JsonArray refs = new io.vertx.core.json.JsonArray();
    for (int i = 0; i < branches; i++) {
      refs.add(new JsonObject().put("$ref", "urn:vertxschemas:branch-" + i + "#"));
    }
    schemaJson.put("oneOf", refs);

    return oneOfOver(branches, new JsonObject());
  }

  private static BodyProcessorException oneOfOver(int branches, JsonObject input) {
    JsonObject schemaJson = new JsonObject();
    io.vertx.core.json.JsonArray refs = new io.vertx.core.json.JsonArray();
    for (int i = 0; i < branches; i++) {
      refs.add(new JsonObject().put("$ref", "urn:vertxschemas:branch-" + i + "#"));
    }
    schemaJson.put("oneOf", refs);

    ValidationExceptionImpl combinator =
        (ValidationExceptionImpl) ValidationException.create("No schema matches", "oneOf", input);
    combinator.setSchema(new StubSchema(schemaJson, null));
    return BodyProcessorException.createValidationError("application/json", combinator);
  }

  private static SchemaBranchResolver resolverOf(java.util.Map<String, io.vertx.json.schema.Schema> byRef) {
    return (ref, scope) -> byRef.get(ref);
  }

  @Test
  @DisplayName("Branches all objecting to the same thing collapse to that one reason")
  void combinatorCollapsesIdenticalBranchFailures() {
    ValidationException missingName =
        schemaFailure("provided object should contain property name", "required", "");
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#", new StubSchema("A Entity", missingName),
            "urn:vertxschemas:branch-1#", new StubSchema("B Entity", missingName));

    String message =
        RequestValidationErrorFormatter.clientMessage(oneOfOver(2), resolverOf(branches));

    assertEquals("Invalid request body: missing required property 'name'", message);
  }

  @Test
  @DisplayName("Branches objecting to different things are listed under their schema titles")
  void combinatorListsDifferingBranchFailures() {
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#",
                new StubSchema(
                    "AiModel Entity",
                    schemaFailure("provided object should contain property fileSize", "required", "")),
            "urn:vertxschemas:branch-1#",
                new StubSchema(
                    "DataBank Entity",
                    schemaFailure("provided object should contain property yearRange", "required", "")));

    String message =
        RequestValidationErrorFormatter.clientMessage(oneOfOver(2), resolverOf(branches));

    assertTrue(message.contains("AiModel Entity: missing required property 'fileSize'"), message);
    assertTrue(message.contains("DataBank Entity: missing required property 'yearRange'"), message);
  }

  @Test
  @DisplayName("A branch failure inside a field keeps the field path")
  void combinatorKeepsBranchFieldPath() {
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#",
                new StubSchema("A Entity", schemaFailure("nope", "pattern", "/name")),
            "urn:vertxschemas:branch-1#",
                new StubSchema("B Entity", schemaFailure("missing", "required", "")));

    String message =
        RequestValidationErrorFormatter.clientMessage(oneOfOver(2), resolverOf(branches));

    assertTrue(message.contains("A Entity: at 'name', does not match the required format"), message);
  }

  @Test
  @DisplayName("Without a resolver the combinator message is unchanged")
  void combinatorWithoutResolverIsUnchanged() {
    assertEquals(
        "Invalid request body: does not match any of the shapes allowed by the API specification",
        RequestValidationErrorFormatter.clientMessage(oneOfOver(2)));
  }

  @Test
  @DisplayName("An unresolvable branch falls back rather than reporting a partial breakdown")
  void combinatorWithUnresolvableBranchFallsBack() {
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#",
            new StubSchema("A Entity", schemaFailure("missing", "required", "")));

    String message =
        RequestValidationErrorFormatter.clientMessage(oneOfOver(2), resolverOf(branches));

    assertEquals(
        "Invalid request body: does not match any of the shapes allowed by the API specification",
        message);
  }

  @Test
  @DisplayName("A branch that accepts the input means the state moved; say nothing extra")
  void combinatorWithPassingBranchFallsBack() {
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#", new StubSchema("A Entity", null),
            "urn:vertxschemas:branch-1#",
                new StubSchema("B Entity", schemaFailure("missing", "required", "")));

    String message =
        RequestValidationErrorFormatter.clientMessage(oneOfOver(2), resolverOf(branches));

    assertEquals(
        "Invalid request body: does not match any of the shapes allowed by the API specification",
        message);
  }

  @Test
  @DisplayName("Too many branches are summarised instead of listed")
  void combinatorWithTooManyBranchesFallsBack() {
    var branches = new java.util.HashMap<String, io.vertx.json.schema.Schema>();
    for (int i = 0; i < 7; i++) {
      branches.put(
          "urn:vertxschemas:branch-" + i + "#",
          new StubSchema("Entity " + i, schemaFailure("missing " + i, "required", "")));
    }

    String message =
        RequestValidationErrorFormatter.clientMessage(oneOfOver(7), resolverOf(branches));

    assertEquals(
        "Invalid request body: does not match any of the shapes allowed by the API specification",
        message);
  }

  @Test
  @DisplayName("Enum failures are shortened so branches collapse instead of repeating value lists")
  void enumReasonIsShortened() {
    ValidationException badEnum =
        schemaFailure("Input doesn't match one of allowed values of enum: [A, B]", "enum", "/kind");
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#", new StubSchema("A Entity", badEnum),
            "urn:vertxschemas:branch-1#", new StubSchema("B Entity", badEnum));

    String message =
        RequestValidationErrorFormatter.clientMessage(oneOfOver(2), resolverOf(branches));

    assertEquals(
        "Invalid request body at 'kind': is not one of the values allowed by the API specification",
        message);
  }

  private static JsonObject shape(String title, String... required) {
    io.vertx.core.json.JsonArray list = new io.vertx.core.json.JsonArray();
    for (String property : required) {
      list.add(property);
    }
    return new JsonObject().put("title", title).put("required", list);
  }

  @Test
  @DisplayName("The shape the payload best fits is the only one reported")
  void combinatorReportsIntendedShapeOnly() {
    JsonObject payload = new JsonObject().put("name", "x").put("yearRange", "2021");
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#",
                new StubSchema(
                    shape("AiModel Entity", "name", "modelType", "fileSize"),
                    schemaFailure("provided object should contain property modelType", "required", "")),
            "urn:vertxschemas:branch-1#",
                new StubSchema(
                    shape("DataBank Entity", "name", "yearRange", "accessPolicy"),
                    schemaFailure(
                        "provided object should contain property accessPolicy", "required", "")));

    String message =
        RequestValidationErrorFormatter.clientMessage(
            oneOfOver(2, payload), resolverOf(branches));

    assertEquals(
        "Invalid request body for DataBank Entity: missing required property 'accessPolicy'",
        message);
  }

  @Test
  @DisplayName("Shapes fitting equally well are all listed rather than one being guessed")
  void combinatorWithTiedShapesListsAll() {
    JsonObject payload = new JsonObject().put("name", "x");
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#",
                new StubSchema(
                    shape("A Entity", "name", "alpha"),
                    schemaFailure("provided object should contain property alpha", "required", "")),
            "urn:vertxschemas:branch-1#",
                new StubSchema(
                    shape("B Entity", "name", "beta"),
                    schemaFailure("provided object should contain property beta", "required", "")));

    String message =
        RequestValidationErrorFormatter.clientMessage(
            oneOfOver(2, payload), resolverOf(branches));

    assertTrue(message.contains("A Entity: missing required property 'alpha'"), message);
    assertTrue(message.contains("B Entity: missing required property 'beta'"), message);
  }

  @Test
  @DisplayName("A longer required list does not win on size alone")
  void combinatorFitIsProportionalNotAbsolute() {
    // wide branch supplies 3 of 6; narrow supplies 2 of 2 minus one -> 1 of 2. Wide fits better.
    JsonObject payload =
        new JsonObject().put("a", 1).put("b", 2).put("c", 3);
    var branches =
        java.util.Map.<String, io.vertx.json.schema.Schema>of(
            "urn:vertxschemas:branch-0#",
                new StubSchema(
                    shape("Wide Entity", "a", "b", "c", "d"),
                    schemaFailure("provided object should contain property d", "required", "")),
            "urn:vertxschemas:branch-1#",
                new StubSchema(
                    shape("Narrow Entity", "x", "y"),
                    schemaFailure("provided object should contain property x", "required", "")));

    String message =
        RequestValidationErrorFormatter.clientMessage(
            oneOfOver(2, payload), resolverOf(branches));

    assertEquals(
        "Invalid request body for Wide Entity: missing required property 'd'", message);
  }

  @Test
  @DisplayName("The parser's own wording is kept for the log, not the caller")
  void parseErrorKeepsRawCauseInLogDetail() {
    String jacksonMessage =
        "Unexpected character ('}' (code 125)): was expecting double-quote to start field name\n"
            + " at [Source: REDACTED; line: 13, column: 2]";
    BodyProcessorException failure =
        BodyProcessorException.createParsingError(
            "application/json", new DecodeException(jacksonMessage));

    assertEquals(
        "Request body is not valid JSON (line 13, column 2)",
        RequestValidationErrorFormatter.clientMessage(failure));
    assertTrue(
        RequestValidationErrorFormatter.logDetail(failure).contains("was expecting double-quote"),
        "operators still need the parser detail");
  }
}
