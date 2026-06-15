package packetanalyzer.dpi;

import java.util.HashMap;
import java.util.Map;

public class ConnectionTracker {
    private final int fpId;
    private final Map<Types.FiveTuple, Types.Connection> connections;

    public ConnectionTracker(int fpId) {
        this.fpId = fpId;
        this.connections = new HashMap<>(); // thread-safe not needed if used strictly per FP
    }

    public Types.Connection getOrCreateConnection(Types.FiveTuple tuple) {
        Types.Connection conn = connections.get(tuple);
        if (conn == null) {
            conn = new Types.Connection();
            conn.tuple = tuple;
            connections.put(tuple, conn);
        }
        return conn;
    }

    public Map<Types.FiveTuple, Types.Connection> getConnections() {
        return connections;
    }

    public int getActiveCount() {
        return connections.size();
    }
}
