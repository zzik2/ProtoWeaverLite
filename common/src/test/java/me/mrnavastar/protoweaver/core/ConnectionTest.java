package me.mrnavastar.protoweaver.core;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import me.mrnavastar.protoweaver.api.ProtoConnectionHandler;
import me.mrnavastar.protoweaver.api.netty.ProtoConnection;
import me.mrnavastar.protoweaver.api.protocol.CompressionType;
import me.mrnavastar.protoweaver.api.protocol.Protocol;
import me.mrnavastar.protoweaver.api.protocol.Side;
import me.mrnavastar.protoweaver.api.protocol.velocity.VelocityAuth;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.zip.GZIPInputStream;

import static org.junit.Assert.*;

public class ConnectionTest {

    public static class Handler implements ProtoConnectionHandler {

        final List<Object> received = new ArrayList<>();
        Side disconnecter;

        @Override
        public void handlePacket(ProtoConnection connection, Object packet) {
            received.add(packet);
        }

        @Override
        public void onDisconnect(ProtoConnection connection) {
            disconnecter = connection.getDisconnecter();
        }
    }

    private Protocol.Builder protocol() {
        return Protocol.create("test", UUID.randomUUID().toString())
                .setServerHandler(Handler.class)
                .setClientHandler(Handler.class)
                .addPacket(String.class);
    }

    @Test
    public void countsServerConnectionsAcrossUpgradeAndClose() {
        Protocol first = protocol().build();
        Protocol next = protocol().build();
        EmbeddedChannel server = new EmbeddedChannel();
        EmbeddedChannel client = new EmbeddedChannel();
        try {
            ProtoConnection connection = new ProtoConnection(first, Side.SERVER, server);
            new ProtoConnection(first, Side.CLIENT, client);
            assertEquals(1, first.getConnections());

            connection.upgradeProtocol(next);
            assertEquals(0, first.getConnections());
            assertEquals(1, next.getConnections());
            connection.upgradeProtocol(next);
            assertEquals(1, next.getConnections());

            connection.disconnect();
            assertEquals(0, next.getConnections());
            assertEquals(Side.SERVER, ((Handler) connection.getHandler()).disconnecter);
        } finally {
            server.finishAndReleaseAll();
            client.finishAndReleaseAll();
        }
        assertEquals(0, first.getConnections());
    }

    @Test
    public void releasesIncompleteFrameOnClose() {
        EmbeddedChannel channel = new EmbeddedChannel();
        try {
            new ProtoConnection(protocol().build(), Side.SERVER, channel);
            ByteBuf partial = Unpooled.buffer().writeInt(100).writeByte(1);
            channel.writeInbound(partial);
            channel.close();
            assertEquals(0, partial.refCnt());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void rejectsInvalidLengthsWithoutWaitingForPayload() {
        for (int length : new int[]{-1, 0, 129, Integer.MAX_VALUE}) {
            EmbeddedChannel channel = new EmbeddedChannel();
            try {
                new ProtoConnection(protocol().setMaxPacketSize(128).build(), Side.SERVER, channel);
                channel.writeInbound(Unpooled.buffer().writeInt(length));
                assertFalse("Invalid frame length: " + length, channel.isOpen());
            } finally {
                channel.finishAndReleaseAll();
            }
        }
    }

    @Test
    public void reassemblesFragmentedAndConsecutivePackets() {
        Protocol protocol = protocol().build();
        EmbeddedChannel channel = new EmbeddedChannel();
        try {
            ProtoConnection connection = new ProtoConnection(protocol, Side.SERVER, channel);
            byte[] first = protocol.serialize("first");
            byte[] second = protocol.serialize("second");
            channel.writeInbound(Unpooled.buffer().writeInt(first.length).writeBytes(first, 0, 2));
            assertTrue(((Handler) connection.getHandler()).received.isEmpty());

            channel.writeInbound(Unpooled.buffer().writeBytes(first, 2, first.length - 2).writeInt(second.length).writeBytes(second));
            assertEquals(List.of("first", "second"), ((Handler) connection.getHandler()).received);
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void rejectsOversizedOutboundPacketAndStillSendsNextPacket() {
        Protocol protocol = protocol().setMaxPacketSize(128).build();
        EmbeddedChannel channel = new EmbeddedChannel();
        try {
            ProtoConnection connection = new ProtoConnection(protocol, Side.SERVER, channel);
            assertFalse(connection.send("x".repeat(1024)).isSuccess());
            assertNull(channel.readOutbound());
            assertTrue(connection.send("ok").isSuccess());
            ByteBuf packet = channel.readOutbound();
            try {
                byte[] bytes = new byte[packet.readInt()];
                packet.readBytes(bytes);
                assertEquals("ok", protocol.deserialize(bytes));
            } finally {
                packet.release();
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void appliesCompressionToInitialProtocol() throws Exception {
        Protocol protocol = protocol().setCompression(CompressionType.GZIP).build();
        EmbeddedChannel channel = new EmbeddedChannel();
        try {
            ProtoConnection connection = new ProtoConnection(protocol, Side.SERVER, channel);
            connection.send("compressed");
            ByteBuf packet = channel.readOutbound();
            try {
                byte[] compressed = new byte[packet.readableBytes()];
                packet.readBytes(compressed);
                try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
                    byte[] length = gzip.readNBytes(4);
                    int size = java.nio.ByteBuffer.wrap(length).getInt();
                    assertEquals("compressed", protocol.deserialize(gzip.readNBytes(size)));
                }
            } finally {
                packet.release();
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    public void closesOnExceptionsWithoutAParseableMessage() {
        for (Exception exception : new Exception[]{new IllegalStateException(), new IllegalStateException("failure")}) {
            EmbeddedChannel channel = new EmbeddedChannel();
            try {
                new ProtoConnection(protocol().build(), Side.SERVER, channel);
                channel.pipeline().fireExceptionCaught(exception);
                channel.checkException();
                assertFalse(channel.isOpen());
            } finally {
                channel.finishAndReleaseAll();
            }
        }
    }

    @Test
    public void duplicatePacketRegistrationDoesNotChangeProtocolHash() {
        Protocol protocol = protocol().build();
        byte[] hash = protocol.getSHA1();
        protocol.modify().addPacket(String.class).build();
        assertArrayEquals(hash, protocol.getSHA1());
    }

    @Test
    public void missingVelocitySecretCannotAuthenticate() {
        VelocityAuth.setSecret(null);
        assertFalse(new VelocityAuth().handleAuth(null, null));
    }
}
