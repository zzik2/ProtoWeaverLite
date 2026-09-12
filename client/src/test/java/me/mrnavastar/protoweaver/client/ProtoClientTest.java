package me.mrnavastar.protoweaver.client;

import org.junit.Test;

import static org.junit.Assert.*;

public class ProtoClientTest {

    @Test
    public void reportsDisconnectedBeforeFirstConnect() {
        ProtoClient client = new ProtoClient("localhost", 25565);
        assertFalse(client.isConnected());
        assertNull(client.getCurrentProtocol());
        client.disconnect();
        assertFalse(client.isConnected());
    }
}
