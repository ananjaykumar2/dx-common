package org.cdpg.dx.auth.appid.client;

import io.grpc.CallCredentials;
import io.grpc.Metadata;
import java.util.concurrent.Executor;

/**
 * gRPC {@link CallCredentials} that attaches a pre-obtained Bearer token to every outbound gRPC
 * call. Instantiated per-call with the token obtained from {@link KeycloakServiceTokenProvider}.
 */
public class BearerTokenCallCredentials extends CallCredentials {

  private static final Metadata.Key<String> AUTHORIZATION_KEY =
      Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);

  private final String token;

  public BearerTokenCallCredentials(String token) {
    this.token = token;
  }

  @Override
  public void applyRequestMetadata(
      RequestInfo requestInfo, Executor appExecutor, MetadataApplier applier) {
    Metadata headers = new Metadata();
    headers.put(AUTHORIZATION_KEY, "Bearer " + token);
    applier.apply(headers);
  }
}
