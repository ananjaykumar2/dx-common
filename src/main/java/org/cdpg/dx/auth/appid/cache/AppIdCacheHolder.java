package org.cdpg.dx.auth.appid.cache;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Static holder for AppId cache instances, shared across verticles within the same JVM.
 *
 * <p>Populated once by DataBrokerVerticle (before ApiServerVerticle starts) and read by
 * ApiServerVerticle to wire the caches into auth handlers.
 *
 * <p>ApiServerVerticles also register per-resolver invalidation callbacks via
 * {@link #addCredentialsInvalidator(Consumer)} so that {@code AppIdRevocationConsumer} can
 * invalidate all caches — including the internal Guava cache in each
 * {@code GrpcAppCredentialsResolver} — with a single call to {@link #invalidateCredentials(String)}.
 */
public class AppIdCacheHolder {

  private static AppIdCacheService appIdCacheService;
  private static AppIdItemAccessCacheService itemAccessCacheService;
  private static final List<Consumer<String>> credentialsInvalidators = new ArrayList<>();

  private AppIdCacheHolder() {}

  public static void register(AppIdCacheService appIdCache, AppIdItemAccessCacheService itemAccessCache) {
    appIdCacheService = appIdCache;
    itemAccessCacheService = itemAccessCache;
  }

  public static AppIdCacheService getAppIdCache() {
    return appIdCacheService;
  }

  public static AppIdItemAccessCacheService getItemAccessCache() {
    return itemAccessCacheService;
  }

  public static synchronized void addCredentialsInvalidator(Consumer<String> invalidator) {
    credentialsInvalidators.add(invalidator);
  }

  public static synchronized void invalidateCredentials(String appId) {
    for (Consumer<String> inv : credentialsInvalidators) {
      inv.accept(appId);
    }
  }
}
