package org.cdpg.dx.common.util;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.pointer.JsonPointer;
import io.vertx.ext.web.validation.BodyProcessorException;
import io.vertx.ext.web.validation.ParameterProcessorException;
import io.vertx.ext.web.validation.RequestPredicateException;
import io.vertx.json.schema.Schema;
import io.vertx.json.schema.ValidationException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Flattens the exceptions thrown by vertx-web-validation / vertx-json-schema into a single readable
 * line.
 *
 * <p>Those exceptions nest a schema {@link ValidationException} inside a request-level one, and
 * their {@code getMessage()} carries only the outermost layer ("Validation error for body
 * application/json: No schema matches"), so the only way to see which field failed used to be the
 * stack trace. This class digs out the useful bits instead: {@link #clientMessage} produces a
 * detail safe to return to the caller, {@link #logDetail} adds the failing keyword and the schema
 * location for whoever reads the logs.
 */
public final class RequestValidationErrorFormatter {

  private static final String BAD_REQUEST_PREFIX = "[Bad Request] ";
  private static final String GENERIC = "Request does not match the API specification";
  private static final Pattern SOURCE_POSITION =
      Pattern.compile("line:\\s*(\\d+),\\s*column:\\s*(\\d+)");

  /**
   * A combinator with more branches than this, or a per-branch breakdown longer than this, is
   * summarised rather than listed: past a handful of shapes the list stops being something a caller
   * can act on and starts being a wall of text in an error field.
   */
  private static final int MAX_BRANCHES = 6;

  private static final int MAX_BREAKDOWN_LENGTH = 400;

  private RequestValidationErrorFormatter() {}

  /** True when the failure comes from OpenAPI request validation rather than business logic. */
  public static boolean isValidationFailure(Throwable failure) {
    return failure instanceof ValidationException
        || failure instanceof BodyProcessorException
        || failure instanceof RequestPredicateException
        || failure instanceof ParameterProcessorException;
  }

  /** Short, client-safe description of what the caller got wrong. */
  public static String clientMessage(Throwable failure) {
    return clientMessage(failure, null);
  }

  /**
   * {@link #clientMessage(Throwable)}, but able to say which field broke inside a failed {@code
   * oneOf} when given a resolver for the combinator's branches. Without one the message is the same
   * as the single-argument form.
   */
  public static String clientMessage(Throwable failure, SchemaBranchResolver branchResolver) {
    if (failure instanceof ParameterProcessorException parameterFailure) {
      return parameterMessage(parameterFailure, branchResolver);
    }
    if (failure instanceof BodyProcessorException bodyFailure) {
      return bodyMessage(bodyFailure, branchResolver);
    }
    if (failure instanceof RequestPredicateException predicateFailure) {
      return strip(predicateFailure.getMessage());
    }
    if (failure instanceof ValidationException schemaFailure) {
      return describe("Invalid request", schemaFailure, branchResolver);
    }
    return GENERIC;
  }

  /** {@link #clientMessage} plus the details that only help whoever reads the logs. */
  public static String logDetail(Throwable failure) {
    return logDetail(failure, null);
  }

  /** {@link #logDetail(Throwable)} with the same branch detail {@link #clientMessage} gets. */
  public static String logDetail(Throwable failure, SchemaBranchResolver branchResolver) {
    StringBuilder detail = new StringBuilder(clientMessage(failure, branchResolver));
    if (failure instanceof BodyProcessorException bodyFailure
        && bodyFailure.getErrorType()
            == BodyProcessorException.BodyProcessorErrorType.PARSING_ERROR) {
      detail.append(" [cause=").append(rootMessage(failure)).append(']');
    }
    ValidationException schemaFailure = rootSchemaFailure(failure);
    if (schemaFailure != null) {
      String constraint = strip(schemaFailure.getMessage());
      if (detail.indexOf(constraint) < 0) {
        detail.append(" [constraint=").append(constraint).append(']');
      }
      if (schemaFailure.keyword() != null) {
        detail.append(" [keyword=").append(schemaFailure.keyword()).append(']');
      }
      Schema schema = schemaFailure.schema();
      if (schema != null && schema.getScope() != null) {
        detail.append(" [schema=").append(schema.getScope().toURI()).append(']');
      }
    }
    return detail.toString();
  }

  private static String parameterMessage(
      ParameterProcessorException failure, SchemaBranchResolver branchResolver) {
    String location =
        failure.getLocation() == null
            ? "request"
            : failure.getLocation().name().toLowerCase(Locale.ROOT);
    String name = failure.getParameterName();
    return switch (failure.getErrorType()) {
      case MISSING_PARAMETER_WHEN_REQUIRED_ERROR ->
          String.format("Missing required %s parameter '%s'", location, name);
      case PARSING_ERROR ->
          String.format("Malformed %s parameter '%s': %s", location, name, rootMessage(failure));
      case VALIDATION_ERROR ->
          describe(
              String.format("Invalid %s parameter '%s'", location, name),
              rootSchemaFailure(failure),
              branchResolver);
    };
  }

  private static String bodyMessage(
      BodyProcessorException failure, SchemaBranchResolver branchResolver) {
    return switch (failure.getErrorType()) {
      case MISSING_MATCHING_BODY_PROCESSOR ->
          String.format(
              "Unsupported request body content type '%s'", failure.getActualContentType());
      case PARSING_ERROR -> parseFailureMessage(failure);
      case VALIDATION_ERROR ->
          describe("Invalid request body", rootSchemaFailure(failure), branchResolver);
    };
  }

  /**
   * Composes the one line the caller sees: {@code <subject> at '<field>': <reason>}, dropping the
   * {@code at} clause when the failing input is the whole thing that was validated (always the case
   * for a single parameter, and for a body whose root object is what failed).
   */
  private static String describe(
      String subject, ValidationException failure, SchemaBranchResolver branchResolver) {
    if (failure == null) {
      return subject + ": " + GENERIC;
    }
    if (isCombinator(failure.keyword())) {
      String expanded = expandCombinator(subject, failure, branchResolver);
      if (expanded != null) {
        return expanded;
      }
    }
    return locate(subject, failure);
  }

  private static String locate(String subject, ValidationException failure) {
    String field = fieldPath(failure.inputScope());
    String location = field == null ? subject : subject + " at '" + field + "'";
    return location + ": " + reason(failure);
  }

  /**
   * Says what actually broke inside a {@code oneOf} that matched nothing, by validating the input
   * against each branch again and reporting what each one objected to.
   *
   * <p>This is deliberately a re-run rather than a read of the exception: the branch failures
   * vert.x attaches are unusable (see {@link #rootSchemaFailure}), whereas {@code validateSync}
   * against a resolved branch is deterministic and gives the same answer on every request. When
   * every branch objects to the same thing — the common case, a field required by all of them —
   * that one reason is the whole message. When they differ, each shape is named so the caller can
   * tell which one they were aiming at.
   *
   * <p>Returns null whenever the breakdown cannot be produced or trusted, leaving the caller with
   * the generic combinator message.
   */
  private static String expandCombinator(
      String subject, ValidationException combinator, SchemaBranchResolver branchResolver) {
    if (branchResolver == null) {
      return null;
    }
    // "More than one schema valid" is the opposite problem: every branch passes, so re-running them
    // has nothing to report.
    if (strip(combinator.getMessage()).startsWith("More than one")) {
      return null;
    }
    Schema schema = combinator.schema();
    if (schema == null || !(schema.getJson() instanceof JsonObject schemaJson)) {
      return null;
    }
    JsonArray branches = schemaJson.getJsonArray(combinator.keyword());
    if (branches == null || branches.isEmpty() || branches.size() > MAX_BRANCHES) {
      return null;
    }

    List<String> labels = new ArrayList<>();
    List<Schema> resolved = new ArrayList<>();
    List<ValidationException> failures = new ArrayList<>();
    for (int index = 0; index < branches.size(); index++) {
      Object entry = branches.getValue(index);
      if (!(entry instanceof JsonObject branchJson)) {
        return null;
      }
      String ref = branchJson.getString("$ref");
      Schema branch = ref == null ? null : branchResolver.resolve(ref, schema.getScope());
      if (branch == null) {
        return null;
      }
      try {
        branch.validateSync(combinator.input());
        // A branch accepting the input contradicts the failure we are explaining, which means the
        // schema's state moved under us. Say nothing rather than something wrong.
        return null;
      } catch (ValidationException branchFailure) {
        labels.add(branchLabel(branch, index));
        resolved.add(branch);
        failures.add(branchFailure);
      } catch (RuntimeException notValidatable) {
        // Typically NoSyncValidationException: this branch still has unresolved refs.
        return null;
      }
    }

    List<String> reasons = failures.stream().map(RequestValidationErrorFormatter::reason).toList();
    if (reasons.stream().distinct().count() == 1) {
      return locate(subject, failures.get(0));
    }

    int intended = intendedBranch(resolved, combinator.input());
    if (intended >= 0) {
      return locateForShape(subject, labels.get(intended), failures.get(intended));
    }

    StringBuilder breakdown = new StringBuilder();
    for (int index = 0; index < failures.size(); index++) {
      if (index > 0) {
        breakdown.append("; ");
      }
      ValidationException branchFailure = failures.get(index);
      String field = fieldPath(branchFailure.inputScope());
      breakdown.append(labels.get(index)).append(": ");
      if (field != null) {
        breakdown.append("at '").append(field).append("', ");
      }
      breakdown.append(reasons.get(index));
    }
    if (breakdown.length() > MAX_BREAKDOWN_LENGTH) {
      return null;
    }
    return subject + ": " + reason(combinator) + " (" + breakdown + ")";
  }

  /**
   * Picks the branch the payload was aimed at, so a caller sending one shape is told what is wrong
   * with <em>that</em> shape instead of reading objections from every shape the endpoint accepts.
   *
   * <p>The fit of a branch is the share of its required properties the payload actually supplies:
   * something addressed to a shape carries nearly all of what that shape asks for, and much less of
   * what its siblings ask for. Using the share rather than the count keeps a branch with a long
   * required list from winning by size alone.
   *
   * <p>Only a strict winner counts. When two branches fit equally well there is no evidence which
   * was meant, and guessing would produce a confident message about the wrong shape — the caller is
   * better served by the full breakdown. Returns -1 in that case, and whenever fit cannot be
   * measured at all (a non-object payload, or a branch that states no required properties).
   */
  private static int intendedBranch(List<Schema> branches, Object input) {
    if (!(input instanceof JsonObject payload)) {
      return -1;
    }
    double bestFit = -1;
    int bestIndex = -1;
    boolean tied = false;
    for (int index = 0; index < branches.size(); index++) {
      if (!(branches.get(index).getJson() instanceof JsonObject branchJson)) {
        return -1;
      }
      JsonArray required = branchJson.getJsonArray("required");
      if (required == null || required.isEmpty()) {
        return -1;
      }
      int supplied = 0;
      for (Object property : required) {
        if (payload.containsKey(String.valueOf(property))) {
          supplied++;
        }
      }
      double fit = (double) supplied / required.size();
      if (fit > bestFit) {
        bestFit = fit;
        bestIndex = index;
        tied = false;
      } else if (fit == bestFit) {
        tied = true;
      }
    }
    return tied ? -1 : bestIndex;
  }

  /**
   * Names the shape alongside the fault, so the caller can see which of the allowed shapes the
   * message is about — and catch it if the payload was aimed at a different one.
   */
  private static String locateForShape(String subject, String label, ValidationException failure) {
    String field = fieldPath(failure.inputScope());
    String location = subject + " for " + label;
    if (field != null) {
      location += " at '" + field + "'";
    }
    return location + ": " + reason(failure);
  }

  /** Prefers the branch's own title, which in a bundled OpenAPI spec names the schema. */
  private static String branchLabel(Schema branch, int index) {
    if (branch.getJson() instanceof JsonObject branchJson) {
      String title = branchJson.getString("title");
      if (title != null && !title.isBlank()) {
        return title;
      }
    }
    return "shape #" + (index + 1);
  }

  private static String reason(ValidationException failure) {
    String message = strip(failure.getMessage());
    String keyword = failure.keyword();
    if (keyword == null) {
      return message;
    }
    return switch (keyword) {
      case "required" -> "missing required property '" + lastToken(message) + "'";
      // Vert.x throws the same oneOf keyword for both "no branch matched" and its opposite,
      // "More than one schema valid", so the message is what tells them apart.
      case "oneOf", "anyOf" ->
          message.startsWith("More than one")
              ? "matches more than one of the shapes allowed by the API specification"
              : "does not match any of the shapes allowed by the API specification";
      case "additionalProperties" -> "contains a property that is not allowed";
      // The raw message carries the regex, which is unreadable in a response. It survives in
      // logDetail, where it is the only record of which pattern failed.
      case "pattern" -> "does not match the required format";
      // Same reasoning as pattern, plus one specific to combinators: branches often allow slightly
      // different value sets for the same field, so keeping the raw list would print a
      // near-identical
      // enumeration once per branch instead of collapsing to the single thing that is wrong.
      case "enum" -> "is not one of the values allowed by the API specification";
      default -> message;
    };
  }

  /**
   * Renders the JSON pointer of the failing input as a field path, e.g. {@code /items/0/name}
   * becomes {@code items[0].name}. Returns null for the document root.
   */
  private static String fieldPath(JsonPointer inputScope) {
    if (inputScope == null || inputScope.isRootPointer()) {
      return null;
    }
    StringBuilder path = new StringBuilder();
    for (String token : inputScope.toString().split("/")) {
      if (token.isEmpty()) {
        continue;
      }
      String decoded = token.replace("~1", "/").replace("~0", "~");
      if (decoded.chars().allMatch(Character::isDigit)) {
        path.append('[').append(decoded).append(']');
      } else {
        if (path.length() > 0) {
          path.append('.');
        }
        path.append(decoded);
      }
    }
    return path.length() == 0 ? null : path.toString();
  }

  /**
   * The innermost schema failure, which is the one that knows the field and the keyword — except
   * that we stop at a combinator.
   *
   * <p>A {@code oneOf} that matches nothing has no single cause: every branch failed, and the
   * validator cannot know which one the caller meant. Vert.x only sometimes attaches one anyway —
   * {@code OneOfValidator.validateAsync} keeps whichever branch future happened to finish last,
   * while {@code validateSync} keeps none. Since a schema starts async and flips to sync once its
   * $refs resolve, descending past the combinator makes the first request against each schema
   * answer differently from every request after it, and the extra detail it yields names an
   * arbitrary branch. Reporting the combinator itself is both stable and honest.
   *
   * <p>The detail is recovered instead by {@link #expandCombinator}, which re-validates the
   * branches rather than trusting what the exception happened to keep.
   */
  private static ValidationException rootSchemaFailure(Throwable failure) {
    ValidationException found = null;
    for (Throwable current = failure;
        current != null && current.getCause() != current;
        current = current.getCause()) {
      if (current instanceof ValidationException schemaFailure) {
        found = schemaFailure;
        if (isCombinator(schemaFailure.keyword())) {
          return found;
        }
      }
    }
    return found;
  }

  private static boolean isCombinator(String keyword) {
    return "oneOf".equals(keyword) || "anyOf".equals(keyword);
  }

  /**
   * A body that is not JSON at all gets a plain sentence plus the coordinates of the fault.
   *
   * <p>Jackson's own wording — "Unexpected character ('}' (code 125)): was expecting double-quote
   * to start field name" — describes the state of a parser, not anything the caller did, and names
   * internals they cannot act on. The line and column are the part that lets them find the typo, so
   * that is what is kept; the raw text stays in {@link #logDetail} for whoever is diagnosing a
   * client that suddenly started sending garbage.
   */
  private static String parseFailureMessage(Throwable failure) {
    Matcher position = SOURCE_POSITION.matcher(strip(innermostMessage(failure)));
    return position.find()
        ? String.format(
            "Request body is not valid JSON (line %s, column %s)",
            position.group(1), position.group(2))
        : "Request body is not valid JSON";
  }

  /** Message of the innermost cause, which for parsing errors is the one that says what broke. */
  private static String rootMessage(Throwable failure) {
    return condense(strip(innermostMessage(failure)));
  }

  private static String innermostMessage(Throwable failure) {
    Throwable current = failure;
    while (current.getCause() != null && current.getCause() != current) {
      current = current.getCause();
    }
    return current.getMessage();
  }

  /**
   * Jackson parse errors arrive as two lines: what broke, then an {@code at [Source: REDACTED …;
   * line: 30, column: 6]} footer. Keep the first line and the coordinates — they are what lets the
   * caller find the fault — and drop the rest, which is Jackson's internal detail and would put a
   * newline in the middle of a JSON string field.
   */
  private static String condense(String message) {
    int footer = message.indexOf('\n');
    if (footer < 0) {
      return message;
    }
    String cause = message.substring(0, footer).trim();
    Matcher position = SOURCE_POSITION.matcher(message.substring(footer));
    return position.find()
        ? String.format("%s (line %s, column %s)", cause, position.group(1), position.group(2))
        : cause;
  }

  private static String lastToken(String message) {
    int lastSpace = message.lastIndexOf(' ');
    return lastSpace < 0 ? message : message.substring(lastSpace + 1);
  }

  private static String strip(String message) {
    if (message == null) {
      return GENERIC;
    }
    return message.startsWith(BAD_REQUEST_PREFIX)
        ? message.substring(BAD_REQUEST_PREFIX.length())
        : message;
  }
}
