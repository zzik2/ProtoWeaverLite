package me.mrnavastar.protoweaver.client;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.Getter;
import lombok.NonNull;
import me.mrnavastar.protoweaver.api.ProtoWeaver;
import me.mrnavastar.protoweaver.api.netty.ProtoConnection;
import me.mrnavastar.protoweaver.api.netty.Sender;
import me.mrnavastar.protoweaver.api.protocol.Protocol;
import me.mrnavastar.protoweaver.api.protocol.Side;
import me.mrnavastar.protoweaver.client.netty.ProtoTrustManager;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.ClientConnectionHandler;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.InternalConnectionHandler;

import javax.net.ssl.SSLException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class ProtoClient {

    @FunctionalInterface
    public interface ConnectionEventHandler {
        void handle(ProtoConnection connection) throws Exception;
    }

    @Getter
    private final InetSocketAddress address;
    private EventLoopGroup workerGroup = null;
    @Getter
    private volatile ProtoConnection connection = null;
    private final SslContext sslContext;
    private final ProtoTrustManager trustManager;
    private final List<ConnectionEventHandler> connectionEstablishedHandlers = new CopyOnWriteArrayList<>();
    private final List<ConnectionEventHandler> connectionLostHandlers = new CopyOnWriteArrayList<>();

    public ProtoClient(@NonNull InetSocketAddress address, @NonNull String hostsFile) {
        try {
            this.address = address;
            trustManager = new ProtoTrustManager(address.getHostName(), address.getPort(), hostsFile);
            // Server identity is verified by its saved fingerprint, not the self-signed certificate's hostname.
            this.sslContext = SslContextBuilder.forClient().trustManager(trustManager).endpointIdentificationAlgorithm(null).build();
        } catch (SSLException e) {
            throw new RuntimeException(e);
        }
    }

    public ProtoClient(@NonNull InetSocketAddress address) {
        this(address.getHostName(), address.getPort());
    }

    public ProtoClient(@NonNull String host, int port, @NonNull String hostsFile) {
        this(new InetSocketAddress(host, port), hostsFile);
    }

    public ProtoClient(@NonNull String host, int port) {
        this(host, port, ".");
    }

    public synchronized ProtoClient connect(@NonNull Protocol protocol) {
        if (workerGroup != null) throw new IllegalStateException("Client is already connecting or connected");
        ProtoWeaver.load(protocol);

        Bootstrap b = new Bootstrap();
        EventLoopGroup group = new NioEventLoopGroup(1);
        workerGroup = group;
        b.group(group);
        b.channel(NioSocketChannel.class);
        b.option(ChannelOption.SO_KEEPALIVE, true);
        b.option(ChannelOption.TCP_NODELAY, true);
        b.handler(new ChannelInitializer<SocketChannel>() {
            @Override
            public void initChannel(@NonNull SocketChannel ch) throws Exception {
                ch.pipeline().addLast("ssl", sslContext.newHandler(ch.alloc(), address.getHostName(), address.getPort()));
                connection = new ProtoConnection(InternalConnectionHandler.getProtocol(), Side.CLIENT, ch);
            }
        });

        ChannelFuture f = b.connect(address);
        new Thread(() -> {
            ProtoConnection activeConnection = null;
            try {
                f.awaitUninterruptibly();
                activeConnection = connection;
                if (f.isSuccess() && activeConnection != null) {
                    ClientConnectionHandler handshake = (ClientConnectionHandler) activeConnection.getHandler();
                    handshake.start(activeConnection, protocol);
                    handshake.awaitReady();

                    if (activeConnection.isOpen() && activeConnection.getProtocol().toString().equals(protocol.toString())) {
                        for (ConnectionEventHandler handler : connectionEstablishedHandlers) {
                            handler.handle(activeConnection);
                        }
                    }
                }

                f.channel().closeFuture().sync();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                protocol.logErr("Connection failed: " + e);
            } finally {
                f.channel().close();
                group.shutdownGracefully();
                synchronized (this) {
                    if (workerGroup == group) {
                        connection = null;
                        workerGroup = null;
                    }
                }
                for (ConnectionEventHandler handler : connectionLostHandlers) {
                    try {
                        handler.handle(activeConnection);
                    } catch (Exception e) {
                        protocol.logErr("Connection lost handler failed: " + e);
                    }
                }
            }
        }, "protoweaver-client-" + address).start();
        return this;
    }

    public boolean isConnected() {
        ProtoConnection activeConnection = connection;
        return activeConnection != null && activeConnection.isOpen()
                && activeConnection.getProtocol() != InternalConnectionHandler.getProtocol();
    }

    public synchronized void disconnect() {
        if (connection != null) connection.disconnect();
        if (workerGroup != null && !workerGroup.isShutdown()) workerGroup.shutdownGracefully();
    }

    public ProtoClient onConnectionEstablished(@NonNull ConnectionEventHandler handler) {
        connectionEstablishedHandlers.add(handler);
        return this;
    }

    public ProtoClient onConnectionLost(@NonNull ConnectionEventHandler handler) {
        this.connectionLostHandlers.add(handler);
        return this;
    }

    public ProtoClient onCertificateRejected(@NonNull ProtoTrustManager.CertificateEventHandler handler) {
        this.trustManager.onCertificateRejected(handler);
        return this;
    }

    public Sender send(@NonNull Object packet) {
        ProtoConnection activeConnection = connection;
        if (activeConnection != null && activeConnection.isOpen()) return activeConnection.send(packet);
        return Sender.NULL;
    }

    public Protocol getCurrentProtocol() {
        ProtoConnection activeConnection = connection;
        return activeConnection == null ? null : activeConnection.getProtocol();
    }
}
