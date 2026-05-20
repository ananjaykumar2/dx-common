package org.cdpg.dx.auth.appid.client;

import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.stub.StreamObserver;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cdpg.dx.auth.appid.v1.AppIdVerificationServiceGrpc;
import org.cdpg.dx.auth.appid.v1.CheckItemAccessRequest;
import org.cdpg.dx.auth.appid.v1.CheckItemAccessResponse;
import org.cdpg.dx.auth.appid.v1.ResolveDelegationRequest;
import org.cdpg.dx.auth.appid.v1.ResolveDelegationResponse;
import org.cdpg.dx.auth.appid.v1.VerifyAppIdRequest;
import org.cdpg.dx.auth.appid.v1.VerifyAppIdResponse;

/**
 * Async gRPC client for the AppIdVerificationService hosted on dx-controlplane.
 *
 * <p>Uses a non-blocking async stub so gRPC callbacks do not block the Vert.x event-loop. The
 * returned {@link Future} is completed on the gRPC callback thread; callers should use {@code
 * .onSuccess()} / {@code .onFailure()} rather than blocking.
 *
 * <p>TLS: uses plaintext ({@code usePlaintext()}). All DX services run on the same Kubernetes
 * cluster — TLS is handled at the service-mesh/ingress level, no additional gRPC-layer TLS needed
 * (OQ3 resolved).
 */
public class AppIdVerificationClient {

  private static final Logger LOGGER = LogManager.getLogger(AppIdVerificationClient.class);

  private final ManagedChannel channel;
  private final AppIdVerificationServiceGrpc.AppIdVerificationServiceStub asyncStub;

  public AppIdVerificationClient(String host, int port) {
    // Docker Swarm DNS names contain underscores (e.g. stack_service), which java.net.URI
    // rejects. Resolving to InetAddress first means gRPC sees the IP as the authority string.
    InetAddress resolved;
    try {
      resolved = InetAddress.getByName(host);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("Cannot resolve controlplane host: " + host, e);
    }
    this.channel =
        NettyChannelBuilder.forAddress(new InetSocketAddress(resolved, port))
            .usePlaintext()
            .keepAliveTime(30, TimeUnit.SECONDS)
            .build();
    this.asyncStub = AppIdVerificationServiceGrpc.newStub(this.channel);
  }

  public Future<ResolveDelegationResponse> resolveDelegation(
      String delegatorSub, String delegateeSub) {
    Promise<ResolveDelegationResponse> promise = Promise.promise();
    asyncStub.resolveDelegation(
        ResolveDelegationRequest.newBuilder()
            .setDelegatorSub(delegatorSub)
            .setDelegateeSub(delegateeSub)
            .build(),
        new StreamObserver<>() {
          @Override
          public void onNext(ResolveDelegationResponse response) {
            promise.complete(response);
          }

          @Override
          public void onError(Throwable t) {
            LOGGER.error(
                "gRPC ResolveDelegation failed delegatorSub={} delegateeSub={}: {}",
                delegatorSub,
                delegateeSub,
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

  /**
   * Sends a VerifyAppId RPC to dx-controlplane.
   *
   * @param appId UUID string — safe to log
   * @param appSecret plaintext secret — NEVER log
   */
  public Future<VerifyAppIdResponse> verify(String appId, String appSecret) {
    Promise<VerifyAppIdResponse> promise = Promise.promise();
    asyncStub.verifyAppId(
        VerifyAppIdRequest.newBuilder().setAppId(appId).setAppSecret(appSecret).build(),
        new StreamObserver<>() {
          @Override
          public void onNext(VerifyAppIdResponse response) {
            promise.complete(response);
          }

          @Override
          public void onError(Throwable t) {
            LOGGER.error("gRPC VerifyAppId failed appId={}: {}", appId, t.getMessage());
            promise.fail(t);
          }

          @Override
          public void onCompleted() {}
        });
    return promise.future();
  }

  /**
   * Sends a CheckItemAccess RPC to dx-controlplane. Called after credentials are already verified
   * (userId from VerifyAppId response).
   *
   * @param userId userId (sub) from the VerifyAppId principal — no extra DB lookup on controlplane
   *     side
   * @param did delegate ID from the {@code did} HTTP header; empty string means no delegation
   */
  public Future<CheckItemAccessResponse> checkItemAccess(
      String userId, String entityId, String did) {
    Promise<CheckItemAccessResponse> promise = Promise.promise();
    asyncStub.checkItemAccess(
        CheckItemAccessRequest.newBuilder()
            .setUserId(userId)
            .setEntityId(entityId)
            .setDid(did != null ? did : "")
            .build(),
        new StreamObserver<>() {
          @Override
          public void onNext(CheckItemAccessResponse response) {
            promise.complete(response);
          }

          @Override
          public void onError(Throwable t) {
            LOGGER.error(
                "gRPC CheckItemAccess failed userId={} entityId={} did={}: {}",
                userId,
                entityId,
                did,
                t.getMessage());
            promise.fail(t);
          }

          @Override
          public void onCompleted() {}
        });
    return promise.future();
  }
}
