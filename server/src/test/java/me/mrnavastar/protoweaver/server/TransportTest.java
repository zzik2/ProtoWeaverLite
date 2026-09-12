package me.mrnavastar.protoweaver.server;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import me.mrnavastar.protoweaver.api.ProtoConnectionHandler;
import me.mrnavastar.protoweaver.api.auth.ServerAuthHandler;
import me.mrnavastar.protoweaver.api.netty.ProtoConnection;
import me.mrnavastar.protoweaver.api.protocol.CompressionType;
import me.mrnavastar.protoweaver.api.protocol.Protocol;
import me.mrnavastar.protoweaver.api.protocol.Side;
import me.mrnavastar.protoweaver.client.ProtoClient;
import me.mrnavastar.protoweaver.client.netty.ProtoTrustManager;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.AuthStatus;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.ClientConnectionHandler;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.InternalConnectionHandler;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.ProtocolStatus;
import me.mrnavastar.protoweaver.server.netty.ProtoDeterminer;
import me.mrnavastar.protoweaver.server.netty.SSLContext;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class TransportTest {

    @Rule
    public TemporaryFolder temporary = new TemporaryFolder();

    public static class Handler implements ProtoConnectionHandler {

        final CompletableFuture<String> received;

        public Handler(CompletableFuture<String> received) {
            this.received = received;
        }

        @Override
        public void onReady(ProtoConnection connection) {
            if (connection.getSide() == Side.SERVER) connection.send("ready");
        }

        @Override
        public void handlePacket(ProtoConnection connection, Object packet) {
            if (connection.getSide() == Side.SERVER) connection.send(packet);
            else if (!packet.equals("ready")) received.complete((String) packet);
        }
    }

    public static class Auth implements ServerAuthHandler {
        @Override
        public boolean handleAuth(ProtoConnection connection, byte[] secret) {
            return secret.length == 1 && secret[0] == 7;
        }
    }

    public static class SlowReadyHandler implements ProtoConnectionHandler {

        private final CountDownLatch entered;
        private final CountDownLatch release;
        private final AtomicBoolean protocolLocked;

        public SlowReadyHandler(CountDownLatch entered, CountDownLatch release, AtomicBoolean protocolLocked) {
            this.entered = entered;
            this.release = release;
            this.protocolLocked = protocolLocked;
        }

        @Override
        public void onReady(ProtoConnection connection) {
            protocolLocked.set(Thread.holdsLock(connection.getProtocol()));
            entered.countDown();
            try {
                if (!release.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Callback was not released");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
    }

    private Protocol protocol(CompressionType compression, CompletableFuture<String> received) {
        return Protocol.create("transport-test", UUID.randomUUID().toString())
                .setServerHandler(Handler.class, received)
                .setClientHandler(Handler.class, received)
                .setCompression(compression)
                .addPacket(String.class)
                .load();
    }

    private ByteBuf frame(Protocol protocol, Object packet) {
        byte[] bytes = protocol.serialize(packet);
        return Unpooled.buffer().writeInt(bytes.length).writeBytes(bytes);
    }

    private EmbeddedChannel channel() {
        return new EmbeddedChannel() {
            @Override
            protected java.net.SocketAddress remoteAddress0() {
                return new InetSocketAddress("localhost", 25565);
            }
        };
    }

    @Test
    public void decodesCompressedPayloadCoalescedWithUpgrade() {
        CompletableFuture<String> received = new CompletableFuture<>();
        Protocol target = protocol(CompressionType.GZIP, received);
        Protocol internal = InternalConnectionHandler.getProtocol();
        EmbeddedChannel client = channel();
        EmbeddedChannel server = channel();
        ByteBuf combined = Unpooled.buffer();
        try {
            ProtoConnection connection = new ProtoConnection(internal, Side.CLIENT, client);
            ((ClientConnectionHandler) connection.getHandler()).start(connection, target);
            ByteBuf auth = frame(internal, AuthStatus.OK);
            ByteBuf upgrade = frame(internal, new ProtocolStatus(internal.toString(), target.toString(), new byte[0], ProtocolStatus.Status.UPGRADE));
            try {
                combined.writeBytes(auth).writeBytes(upgrade);
            } finally {
                auth.release();
                upgrade.release();
            }

            new ProtoConnection(target, Side.SERVER, server).send("coalesced");
            ByteBuf encoded = server.readOutbound();
            try {
                combined.writeBytes(encoded);
            } finally {
                encoded.release();
            }
            client.writeInbound(combined.retain());
            assertEquals("coalesced", received.getNow(null));
            assertTrue(client.isOpen());
        } finally {
            combined.release();
            client.finishAndReleaseAll();
            server.finishAndReleaseAll();
        }
    }

    @Test
    public void detectsProtocolFromNonzeroReaderIndex() {
        EmbeddedChannel channel = new EmbeddedChannel(new ProtoDeterminer(true));
        try {
            ByteBuf bytes = Unpooled.buffer().writeInt(0x12345678).writeByte(0).writeByte(99);
            ByteBuf packet = frame(InternalConnectionHandler.getProtocol(), new ProtocolStatus("protoweaver:internal", "missing:protocol", new byte[0], ProtocolStatus.Status.START));
            bytes.writeBytes(packet);
            packet.release();
            bytes.skipBytes(4);
            channel.writeInbound(bytes);
            assertFalse(channel.isOpen());
            ByteBuf response = channel.readOutbound();
            assertNotNull(response);
            response.release();
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void initializesTlsRepeatedlyAndMatchesExactHost() throws Exception {
        Path keys = temporary.newFolder("keys").toPath();
        SSLContext.init(keys.toString());
        SSLContext.init(keys.toString());
        X509Certificate certificate;
        try (InputStream input = Files.newInputStream(keys.resolve("cert.pem"))) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        Path hosts = temporary.newFolder("hosts").toPath();
        Files.writeString(hosts.resolve("protoweaver.hosts"), "localhost:255650=00\n");
        ProtoTrustManager manager = new ProtoTrustManager("localhost", 25565, hosts.toString());
        ProtoTrustManager another = new ProtoTrustManager("localhost", 25565, hosts.toString());
        manager.checkServerTrusted(new X509Certificate[]{certificate}, "RSA");
        assertTrue(Files.readString(hosts.resolve("protoweaver.hosts")).contains("localhost:25565="));

        Path changedKeys = temporary.newFolder("changed-keys").toPath();
        SSLContext.init(changedKeys.toString());
        try (InputStream input = Files.newInputStream(changedKeys.resolve("cert.pem"))) {
            X509Certificate changed = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
            assertThrows(CertificateException.class, () -> another.checkServerTrusted(new X509Certificate[]{changed}, "RSA"));
        }
    }

    @Test
    public void enforcesConnectionLimitAfterAuthentication() throws Exception {
        Protocol target = protocol(CompressionType.NONE, new CompletableFuture<>());
        target.modify().setMaxConnections(1).setServerAuthHandler(Auth.class).build();
        Protocol internal = InternalConnectionHandler.getProtocol();
        EmbeddedChannel first = channel();
        EmbeddedChannel second = channel();
        try {
            ProtoConnection firstConnection = new ProtoConnection(internal, Side.SERVER, first);
            ProtoConnection secondConnection = new ProtoConnection(internal, Side.SERVER, second);
            ProtocolStatus start = new ProtocolStatus(internal.toString(), target.toString(), target.getSHA1(), ProtocolStatus.Status.START);
            firstConnection.getHandler().handlePacket(firstConnection, start);
            secondConnection.getHandler().handlePacket(secondConnection, start);
            firstConnection.getHandler().handlePacket(firstConnection, new byte[]{7});
            secondConnection.getHandler().handlePacket(secondConnection, new byte[]{7});
            assertTrue(first.isOpen());
            assertFalse(second.isOpen());
            assertEquals(1, target.getConnections());
        } finally {
            first.finishAndReleaseAll();
            second.finishAndReleaseAll();
        }
        assertEquals(0, target.getConnections());
    }

    @Test
    public void slowReadyCallbackDoesNotBlockAnotherConnectionsAdmission() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean protocolLocked = new AtomicBoolean();
        Protocol target = Protocol.create("transport-test", UUID.randomUUID().toString())
                .setServerHandler(SlowReadyHandler.class, entered, release, protocolLocked)
                .setServerAuthHandler(Auth.class)
                .setMaxConnections(1)
                .load();
        Protocol internal = InternalConnectionHandler.getProtocol();
        EmbeddedChannel first = channel();
        EmbeddedChannel second = channel();
        var workers = Executors.newFixedThreadPool(2);
        try {
            ProtoConnection firstConnection = new ProtoConnection(internal, Side.SERVER, first);
            ProtoConnection secondConnection = new ProtoConnection(internal, Side.SERVER, second);
            ProtocolStatus start = new ProtocolStatus(internal.toString(), target.toString(), target.getSHA1(), ProtocolStatus.Status.START);
            firstConnection.getHandler().handlePacket(firstConnection, start);
            secondConnection.getHandler().handlePacket(secondConnection, start);

            var firstAuth = workers.submit(() -> {
                firstConnection.getHandler().handlePacket(firstConnection, new byte[]{7});
                return null;
            });
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            var secondAuth = workers.submit(() -> {
                secondConnection.getHandler().handlePacket(secondConnection, new byte[]{7});
                return null;
            });
            secondAuth.get(5, TimeUnit.SECONDS);

            assertFalse(firstAuth.isDone());
            assertFalse(protocolLocked.get());
            assertFalse(second.isOpen());
            assertEquals(1, target.getConnections());
            release.countDown();
            firstAuth.get(5, TimeUnit.SECONDS);
        } finally {
            release.countDown();
            workers.shutdown();
            assertTrue(workers.awaitTermination(10, TimeUnit.SECONDS));
            first.finishAndReleaseAll();
            second.finishAndReleaseAll();
        }
        assertEquals(0, target.getConnections());
    }

    @Test
    public void exchangesTlsPacketsForEveryCompressionAndReconnectsFromCallback() throws Exception {
        SSLContext.init(temporary.newFolder("tls").toString());
        NioEventLoopGroup group = new NioEventLoopGroup(2);
        Channel server = new ServerBootstrap().group(group).channel(NioServerSocketChannel.class)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) {
                        ProtoDeterminer.registerToPipeline(channel);
                    }
                }).bind("127.0.0.1", 0).sync().channel();
        try {
            for (CompressionType compression : CompressionType.values()) {
                CompletableFuture<String> received = new CompletableFuture<>();
                Protocol protocol = protocol(compression, received);
                ProtoClient client = new ProtoClient((InetSocketAddress) server.localAddress(), temporary.newFolder().toString());
                CountDownLatch lost = new CountDownLatch(2);
                AtomicInteger connections = new AtomicInteger();
                CompletableFuture<Void> reconnected = new CompletableFuture<>();
                client.onConnectionEstablished(connection -> {
                    if (connections.incrementAndGet() == 1) connection.send("echo");
                    else reconnected.complete(null);
                });
                client.onConnectionLost(connection -> {
                    if (lost.getCount() == 2) client.connect(protocol);
                    lost.countDown();
                });
                try {
                    client.connect(protocol);
                    assertEquals("echo", received.get(10, TimeUnit.SECONDS));
                    assertTrue(client.isConnected());
                    client.disconnect();
                    reconnected.get(10, TimeUnit.SECONDS);
                    assertTrue(client.isConnected());
                    client.disconnect();
                    assertTrue(lost.await(10, TimeUnit.SECONDS));
                    assertFalse(client.isConnected());
                } finally {
                    client.disconnect();
                }
            }

            Path rejectedHosts = temporary.newFolder("rejected-hosts").toPath();
            ProtoClient rejected = new ProtoClient((InetSocketAddress) server.localAddress(), rejectedHosts.toString());
            Files.writeString(rejectedHosts.resolve("protoweaver.hosts"), rejected.getAddress().getHostName() + ":" + rejected.getAddress().getPort() + "=00\n");
            CountDownLatch certificateRejected = new CountDownLatch(1);
            CountDownLatch disconnected = new CountDownLatch(1);
            rejected.onCertificateRejected((expected, actual) -> certificateRejected.countDown());
            rejected.onConnectionLost(connection -> disconnected.countDown());
            try {
                rejected.connect(protocol(CompressionType.NONE, new CompletableFuture<>()));
                assertTrue(certificateRejected.await(10, TimeUnit.SECONDS));
                assertTrue(disconnected.await(10, TimeUnit.SECONDS));
                assertFalse(rejected.isConnected());
            } finally {
                rejected.disconnect();
            }
        } finally {
            server.close().sync();
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS).sync();
        }
    }
}
