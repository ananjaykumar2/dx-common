package org.cdpg.dx.cat.client;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.StreamObserver;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.client.BearerTokenCallCredentials;
import org.cdpg.dx.cat.item.v1.CatItemServiceGrpc;
import org.cdpg.dx.cat.item.v1.GetItemRequest;
import org.cdpg.dx.cat.item.v1.GetItemResponse;
import org.cdpg.dx.cat.item.v1.PatchItemRequest;
import org.cdpg.dx.cat.item.v1.PatchItemResponse;

/**
 * Async gRPC client for the CatItemService (catalogue item lookup/patch).
 *
 * <p>Uses a non-blocking async stub so gRPC callbacks do not block the Vert.x event-loop. The
 * returned {@link Future} is completed on the gRPC callback thread; callers should use {@code
 * .onSuccess()} / {@code .onFailure()} rather than blocking.
 *
 * <p>TLS: uses plaintext ({@code usePlaintext()}). All DX services run on the same Kubernetes
 * cluster — TLS is handled at the service-mesh/ingress level, no additional gRPC-layer TLS needed.
 */
public class CatItemClient {

  private static final Logger LOGGER = LogManager.getLogger(CatItemClient.class);

  private final ManagedChannel channel;
  private final CatItemServiceGrpc.CatItemServiceStub asyncStub;

  public CatItemClient(String host, int port) {
    InetAddress resolved;
    try {
      resolved = InetAddress.getByName(host);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("Cannot resolve cat host: " + host, e);
    }
    this.channel =
        NettyChannelBuilder.forAddress(new InetSocketAddress(resolved, port))
            .usePlaintext()
            .keepAliveTime(30, TimeUnit.SECONDS)
            .build();
    this.asyncStub = CatItemServiceGrpc.newStub(this.channel);
  }

  /**
   * Sends a GetItem RPC authenticated with a service identity token. The caller acts on behalf of an
   * end user whose identity (userId, roles, organizationId) it forwards here.
   *
   * @param itemId catalogue item UUID
   * @param userId acting user's sub; empty = anonymous (public items only)
   * @param roles acting user's realm roles — drives ownership/admin checks
   * @param organizationId acting user's org UUID; empty → server resolves from Keycloak by userId
   * @param serviceToken bearer token obtained via {@code KeycloakServiceTokenProvider}
   */
  public Future<GetItemResponse> getItem(
      String itemId,
      String userId,
      List<String> roles,
      String organizationId,
      String serviceToken) {
    Promise<GetItemResponse> promise = Promise.promise();
    GetItemRequest.Builder request =
        GetItemRequest.newBuilder()
            .setItemId(itemId != null ? itemId : "")
            .setUserId(userId != null ? userId : "")
            .setOrganizationId(organizationId != null ? organizationId : "");
    if (roles != null) {
      request.addAllRoles(roles);
    }
    asyncStub
        .withCallCredentials(new BearerTokenCallCredentials(serviceToken))
        .getItem(
            request.build(),
            new StreamObserver<>() {
              @Override
              public void onNext(GetItemResponse response) {
                promise.complete(response);
              }

              @Override
              public void onError(Throwable t) {
                LOGGER.error(
                    "gRPC GetItem failed itemId={} userId={}: {}", itemId, userId, t.getMessage());
                promise.fail(t);
              }

              @Override
              public void onCompleted() {}
            });
    return promise.future();
  }

  /**
   * Sends a PatchItem RPC authenticated with a service identity token. The caller acts on behalf of
   * an end user whose identity (userId, roles, organizationId) it forwards here.
   *
   * @param itemId catalogue item UUID
   * @param userId acting user's sub
   * @param roles acting user's realm roles
   * @param organizationId acting user's org UUID; empty → server resolves from Keycloak by userId
   * @param patchJson JSON object of fields to patch
   * @param serviceToken bearer token obtained via {@code KeycloakServiceTokenProvider}
   */
  public Future<PatchItemResponse> patchItem(
      String itemId,
      String userId,
      List<String> roles,
      String organizationId,
      String patchJson,
      String serviceToken) {
    Promise<PatchItemResponse> promise = Promise.promise();
    PatchItemRequest.Builder request =
        PatchItemRequest.newBuilder()
            .setItemId(itemId != null ? itemId : "")
            .setUserId(userId != null ? userId : "")
            .setOrganizationId(organizationId != null ? organizationId : "")
            .setPatchJson(patchJson != null ? patchJson : "");
    if (roles != null) {
      request.addAllRoles(roles);
    }
    asyncStub
        .withCallCredentials(new BearerTokenCallCredentials(serviceToken))
        .patchItem(
            request.build(),
            new StreamObserver<>() {
              @Override
              public void onNext(PatchItemResponse response) {
                promise.complete(response);
              }

              @Override
              public void onError(Throwable t) {
                LOGGER.error(
                    "gRPC PatchItem failed itemId={} userId={}: {}",
                    itemId,
                    userId,
                    t.getMessage());
                promise.fail(t);
              }

              @Override
              public void onCompleted() {}
            });
    return promise.future();
  }

  /** Initiates a graceful shutdown of the underlying channel. Call during application teardown. */
  public void shutdown() throws InterruptedException {
    channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
  }
}
