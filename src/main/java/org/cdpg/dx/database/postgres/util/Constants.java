package org.cdpg.dx.database.postgres.util;

public class Constants {
  public static final int DB_RECONNECT_ATTEMPTS = 2;
  public static final long DB_RECONNECT_INTERVAL_MS = 10;
  public static final String DEFAULT_SORTING_ORDER = "DESC";
  public static final String DEFAULT_SORTING_FIELD = "created_at";
  public static final String SERVICE_ADDRESS_KEY = "serviceAddress";

  /** Default pg_trgm similarity threshold for fuzzy search (0-1). Lower = more lenient. */
  public static final double DEFAULT_FUZZY_SIMILARITY_THRESHOLD = 0.2;
}
