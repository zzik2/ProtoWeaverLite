package me.mrnavastar.protoweaver.core.netty;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import lombok.Setter;
import me.mrnavastar.protoweaver.api.ProtoConnectionHandler;
import me.mrnavastar.protoweaver.api.netty.ProtoConnection;
import me.mrnavastar.protoweaver.api.netty.Sender;
import me.mrnavastar.protoweaver.api.protocol.CompressionType;
import me.mrnavastar.protoweaver.api.protocol.Side;
import me.mrnavastar.protoweaver.core.util.ProtoConstants;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class ProtoPacketHandler extends ByteToMessageDecoder {

    private final ConcurrentHashMap<String, Integer> connectionCount;

    private final ProtoConnection connection;
    @Setter
    private ProtoConnectionHandler handler;
    private ChannelHandlerContext ctx;
    private boolean sendHeader;

    public ProtoPacketHandler(ProtoConnection connection, ConcurrentHashMap<String, Integer> connectionCount) {
        this.connection = connection;
        this.connectionCount = connectionCount;
        this.sendHeader = connection.getSide() == Side.CLIENT;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        try {
            super.channelInactive(ctx);
        } finally {
            if (connection.getSide() == Side.SERVER) {
                connectionCount.computeIfPresent(connection.getProtocol().toString(), (name, count) -> count <= 1 ? null : count - 1);
            }
            try {
                this.handler.onDisconnect(connection);
            } catch (Exception e) {
                connection.getProtocol().logErr("Threw an error on disconnect!");
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf byteBuf, List<Object> list) {
        // Ensure the whole packet has arrived before trying to decode
        if (byteBuf.readableBytes() < 4) return;
        byteBuf.markReaderIndex();
        int packetLen = byteBuf.readInt();
        if (packetLen <= 0 || packetLen > connection.getProtocol().getMaxPacketSize()) {
            connection.getProtocol().logWarn("Invalid packet length: " + packetLen);
            byteBuf.skipBytes(byteBuf.readableBytes());
            ctx.close();
            return;
        }
        if (byteBuf.readableBytes() < packetLen) {
            byteBuf.resetReaderIndex();
            return;
        }

        Object packet = null;
        CompressionType previousCompression = connection.getProtocol().getCompression();
        try {
            byte[] bytes = new byte[packetLen];
            byteBuf.readBytes(bytes);
            packet = connection.getProtocol().deserialize(bytes);
            handler.handlePacket(connection, packet);

        } catch (IllegalArgumentException e) {
            connection.getProtocol().logWarn("Ignoring an " + e.getMessage());
        } catch (Exception e) {
            if (packet != null) connection.getProtocol().logErr("Threw an error when trying to handle: " + packet.getClass() + "!");
            e.printStackTrace();
        } finally {
            // Bytes following the upgrade may already be buffered before the compression decoder is installed.
            if (previousCompression == CompressionType.NONE && connection.getProtocol().getCompression() != CompressionType.NONE
                    && ctx.channel().isOpen() && byteBuf.isReadable()) {
                ctx.pipeline().context("compressionEncoder").fireChannelRead(byteBuf.readRetainedSlice(byteBuf.readableBytes()));
            }
        }
    }

    public synchronized Sender send(Object packet) {
        try {
            byte[] packetBuf = connection.getProtocol().serialize(packet);
            if (packetBuf.length == 0) return new Sender(connection, ctx.newSucceededFuture(), false);
            if (packetBuf.length > connection.getProtocol().getMaxPacketSize()) {
                throw new IllegalArgumentException("oversized packet: " + packetBuf.length);
            }

            ByteBuf buf = ctx.alloc().buffer(packetBuf.length + (sendHeader ? 6 : 4));
            if (sendHeader) {
                buf.writeByte(0);
                buf.writeByte(ProtoConstants.PROTOWEAVER_MAGIC_BYTE);
                sendHeader = false;
            }
            buf.writeInt(packetBuf.length); // Packet Len
            buf.writeBytes(packetBuf);

            return new Sender(connection, ctx.writeAndFlush(buf), true);

        } catch (IllegalArgumentException e) {
            connection.getProtocol().logErr("Tried to send an " + e.getMessage());
            return new Sender(connection, ctx.newSucceededFuture(), false);
        } catch (Exception e) {
            connection.getProtocol().logErr("Threw an error when trying to send: " + packet.getClass() + "!");
            e.printStackTrace();
            return new Sender(connection, ctx.newSucceededFuture(), false);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        connection.getProtocol().logWarn("Connection error: " + cause);
        ctx.close();
    }
}
