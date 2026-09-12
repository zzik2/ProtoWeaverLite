package me.mrnavastar.protoweaver.core.protocol.protoweaver;

import lombok.SneakyThrows;
import me.mrnavastar.protoweaver.api.ProtoConnectionHandler;
import me.mrnavastar.protoweaver.api.ProtoWeaver;
import me.mrnavastar.protoweaver.api.auth.ServerAuthHandler;
import me.mrnavastar.protoweaver.api.netty.ProtoConnection;
import me.mrnavastar.protoweaver.api.netty.Sender;
import me.mrnavastar.protoweaver.api.protocol.Protocol;
import me.mrnavastar.protoweaver.api.protocol.Side;
import me.mrnavastar.protoweaver.core.util.ProtoConstants;

import java.util.Arrays;

public class ServerConnectionHandler extends InternalConnectionHandler implements ProtoConnectionHandler {

    private boolean authenticated = false;
    private Protocol nextProtocol = null;
    private ServerAuthHandler authHandler = null;

    @SneakyThrows
    @Override
    public void handlePacket(ProtoConnection connection, Object packet) {
        if (packet instanceof ProtocolStatus status) {
            switch (status.getStatus()) {
                case START -> {
                    authenticated = false;
                    authHandler = null;
                    // Check if protocol loaded
                    nextProtocol = ProtoWeaver.getLoadedProtocol(status.getNextProtocol());
                    if (nextProtocol == null) {
                        protocolNotLoaded(connection, status.getNextProtocol());
                        return;
                    }

                    if (!ProtoConstants.PROTOWEAVER_VERSION.equals(status.getProtoweaverVersion())) {
                        nextProtocol.logWarn("Client connecting with ProtoWeaver version: " + status.getProtoweaverVersion() + ", but server is running: " + ProtoConstants.PROTOWEAVER_VERSION + ". There could be unexpected issues.");
                    }

                    if (nextProtocol.getMaxConnections() != -1 && nextProtocol.getConnections() >= nextProtocol.getMaxConnections()) {
                        status.setStatus(ProtocolStatus.Status.FULL);
                        disconnectIfNeverUpgraded(connection, connection.send(status));
                        return;
                    }

                    if (!Arrays.equals(nextProtocol.getSHA1(), status.getNextSHA1())) {
                        nextProtocol.logErr("Mismatch with protocol version on the client!");
                        nextProtocol.logErr("Double check that all packets are registered in the same order and all settings are the same.");

                        status.setStatus(ProtocolStatus.Status.MISMATCH);
                        disconnectIfNeverUpgraded(connection, connection.send(status));
                        return;
                    }

                    if (nextProtocol.requiresAuth(Side.SERVER)) {
                        authHandler = nextProtocol.newServerAuthHandler();
                        connection.send(AuthStatus.REQUIRED);
                        return;
                    }

                    authenticated = true;
                }
                case MISSING -> {
                    protocol.logErr("Protocol is not loaded on client!");
                    disconnectIfNeverUpgraded(connection);
                    return;
                }
            }
        }

        // Authenticate client
        if (authHandler != null && packet instanceof byte[] secret) {
            authenticated = authHandler.handleAuth(connection, secret);
        }

        if (!authenticated) {
            Sender sender = connection.send(AuthStatus.DENIED);
            disconnectIfNeverUpgraded(connection, sender);
            return;
        }

        connection.upgradeProtocol(nextProtocol);
        if (connection.isOpen() && connection.getProtocol() == nextProtocol) {
            nextProtocol.logInfo("Connected to: " + connection.getRemoteAddress());
        }
    }

    /**
     * Called by ProtoConnection while holding the target protocol's monitor, before changing the connection state.
     */
    public boolean confirmUpgrade(ProtoConnection connection, Protocol targetProtocol) {
        if (targetProtocol.getMaxConnections() != -1 && targetProtocol.getConnections() >= targetProtocol.getMaxConnections()) {
            Sender sender = connection.send(new ProtocolStatus(connection.getProtocol().toString(), targetProtocol.toString(), new byte[0], ProtocolStatus.Status.FULL));
            disconnectIfNeverUpgraded(connection, sender);
            return false;
        }

        connection.send(AuthStatus.OK);
        connection.send(new ProtocolStatus(connection.getProtocol().toString(), targetProtocol.toString(), new byte[0], ProtocolStatus.Status.UPGRADE));
        return true;
    }

    @Override
    public void onDisconnect(ProtoConnection connection) {
        protocol.logInfo("Disconnected from: " + connection.getRemoteAddress());
    }
}
