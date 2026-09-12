package me.mrnavastar.protoweaver.core;

import me.mrnavastar.protoweaver.api.ProtoWeaver;
import me.mrnavastar.protoweaver.api.protocol.Protocol;
import me.mrnavastar.protoweaver.api.protocol.Side;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.ClientConnectionHandler;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.InternalConnectionHandler;
import me.mrnavastar.protoweaver.core.protocol.protoweaver.ServerConnectionHandler;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class InternalProtocolTest {

    @Test
    public void cancellationOnlyExemptsTheExactInternalProtocol() {
        assertNull(ProtoWeaver.getLoadedProtocol("protoweaver:internal"));
        Protocol sharedNamespace = Protocol.create("protoweaver", "cancel-test").build();
        Protocol sharedName = Protocol.create("cancel-test", "internal").build();
        List<Protocol> visited = new ArrayList<>();
        ProtoWeaver.PRE_PROTOCOL_LOADED.register((protocol, cancelable) -> cancelable.cancel());
        ProtoWeaver.PRE_PROTOCOL_LOADED.register((protocol, cancelable) -> visited.add(protocol));

        ProtoWeaver.load(sharedNamespace);
        ProtoWeaver.load(sharedName);
        Protocol internal = InternalConnectionHandler.getProtocol();

        assertNull(ProtoWeaver.getLoadedProtocol(sharedNamespace.toString()));
        assertNull(ProtoWeaver.getLoadedProtocol(sharedName.toString()));
        assertSame(internal, ProtoWeaver.getLoadedProtocol("protoweaver:internal"));
        assertEquals(List.of(internal), visited);
        assertTrue(internal.newConnectionHandler(Side.SERVER) instanceof ServerConnectionHandler);
        assertTrue(internal.newConnectionHandler(Side.CLIENT) instanceof ClientConnectionHandler);
    }
}
