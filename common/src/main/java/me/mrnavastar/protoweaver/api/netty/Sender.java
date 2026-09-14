package me.mrnavastar.protoweaver.api.netty;

import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.concurrent.CompletableFuture;

/**
 * A wrapper that allows for closing the connection after the previously sent packet is done sending.
 */
@RequiredArgsConstructor
public class Sender {

    public static Sender NULL = new Sender(null, null, false);

    private final ProtoConnection connection;
    private final ChannelFuture future;
    @Getter
    private final boolean success;

    /** Completes when the local channel finishes writing, without acknowledging peer receipt. */
    public CompletableFuture<Void> completion() {
        if (!success || future == null) return CompletableFuture.failedFuture(new IllegalStateException("Packet was not accepted for writing"));
        CompletableFuture<Void> result = new CompletableFuture<>();
        future.addListener((ChannelFutureListener) written -> {
            if (written.isSuccess()) result.complete(null);
            else result.completeExceptionally(written.cause() == null ? new IllegalStateException("Packet write was cancelled") : written.cause());
        });
        return result;
    }

    /**
     * Closes the connection after the previously sent packet is done sending.
     */
    public void disconnect() {
        if (future != null) future.addListener((ChannelFutureListener) channelFuture -> connection.disconnect());
    }
}
