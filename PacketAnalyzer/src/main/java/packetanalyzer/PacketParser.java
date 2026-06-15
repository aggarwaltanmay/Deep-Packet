package packetanalyzer;

import packetanalyzer.models.EtherType;
import packetanalyzer.models.ParsedPacket;
import packetanalyzer.models.Protocol;
import packetanalyzer.models.RawPacket;
import packetanalyzer.models.TCPFlags;

public class PacketParser {

    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.timestampSec = raw.tsSec;
        parsed.timestampUsec = raw.tsUsec;

        byte[] data = raw.data;
        int len = data.length;
        int[] offset = {0};

        // Parse Ethernet header first
        if (!parseEthernet(data, len, parsed, offset)) {
            return false;
        }

        // Parse IP layer if it's an IPv4 packet
        if (parsed.etherType == EtherType.IPv4) {
            if (!parseIPv4(data, len, parsed, offset)) {
                return false;
            }

            // Parse transport layer based on protocol
            if (parsed.protocol == Protocol.TCP) {
                if (!parseTCP(data, len, parsed, offset)) {
                    return false;
                }
            } else if (parsed.protocol == Protocol.UDP) {
                if (!parseUDP(data, len, parsed, offset)) {
                    return false;
                }
            }
        }

        // Set payload information
        if (offset[0] < len) {
            parsed.payloadLength = len - offset[0];
            parsed.payloadData = new byte[parsed.payloadLength];
            System.arraycopy(data, offset[0], parsed.payloadData, 0, parsed.payloadLength);
        } else {
            parsed.payloadLength = 0;
            parsed.payloadData = null;
        }

        return true;
    }

    private static boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        final int ETH_HEADER_LEN = 14;

        if (len < ETH_HEADER_LEN) {
            return false;
        }

        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);

        // EtherType is bytes 12-13, big-endian
        parsed.etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);

        offset[0] = ETH_HEADER_LEN;
        return true;
    }

    private static boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        final int MIN_IP_HEADER_LEN = 20;

        if (len < offset[0] + MIN_IP_HEADER_LEN) {
            return false;
        }

        int start = offset[0];
        
        int versionIhl = data[start] & 0xFF;
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;

        if (parsed.ipVersion != 4) {
            return false;
        }

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < start + ipHeaderLen) {
            return false;
        }

        parsed.ttl = data[start + 8] & 0xFF;
        parsed.protocol = data[start + 9] & 0xFF;

        parsed.srcIp = ipToString(data, start + 12);
        parsed.destIp = ipToString(data, start + 16);

        parsed.hasIp = true;
        offset[0] += ipHeaderLen;

        return true;
    }

    private static boolean parseTCP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        final int MIN_TCP_HEADER_LEN = 20;

        if (len < offset[0] + MIN_TCP_HEADER_LEN) {
            return false;
        }

        int start = offset[0];

        parsed.srcPort = ((data[start] & 0xFF) << 8) | (data[start + 1] & 0xFF);
        parsed.destPort = ((data[start + 2] & 0xFF) << 8) | (data[start + 3] & 0xFF);

        parsed.seqNumber = Integer.toUnsignedLong(
            ((data[start + 4] & 0xFF) << 24) |
            ((data[start + 5] & 0xFF) << 16) |
            ((data[start + 6] & 0xFF) << 8) |
            (data[start + 7] & 0xFF)
        );

        parsed.ackNumber = Integer.toUnsignedLong(
            ((data[start + 8] & 0xFF) << 24) |
            ((data[start + 9] & 0xFF) << 16) |
            ((data[start + 10] & 0xFF) << 8) |
            (data[start + 11] & 0xFF)
        );

        int dataOffsetRaw = data[start + 12] & 0xFF;
        int dataOffset = (dataOffsetRaw >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;

        parsed.tcpFlags = data[start + 13] & 0xFF;

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < start + tcpHeaderLen) {
            return false;
        }

        parsed.hasTcp = true;
        offset[0] += tcpHeaderLen;

        return true;
    }

    private static boolean parseUDP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        final int UDP_HEADER_LEN = 8;

        if (len < offset[0] + UDP_HEADER_LEN) {
            return false;
        }

        int start = offset[0];

        parsed.srcPort = ((data[start] & 0xFF) << 8) | (data[start + 1] & 0xFF);
        parsed.destPort = ((data[start + 2] & 0xFF) << 8) | (data[start + 3] & 0xFF);

        parsed.hasUdp = true;
        offset[0] += UDP_HEADER_LEN;

        return true;
    }

    private static String macToString(byte[] data, int start) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", data[start + i] & 0xFF));
        }
        return sb.toString();
    }

    private static String ipToString(byte[] data, int start) {
        return (data[start] & 0xFF) + "." +
               (data[start + 1] & 0xFF) + "." +
               (data[start + 2] & 0xFF) + "." +
               (data[start + 3] & 0xFF);
    }

    public static String protocolToString(int protocol) {
        switch (protocol) {
            case Protocol.ICMP: return "ICMP";
            case Protocol.TCP:  return "TCP";
            case Protocol.UDP:  return "UDP";
            default: return "Unknown(" + protocol + ")";
        }
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder result = new StringBuilder();
        if ((flags & TCPFlags.SYN) != 0) result.append("SYN ");
        if ((flags & TCPFlags.ACK) != 0) result.append("ACK ");
        if ((flags & TCPFlags.FIN) != 0) result.append("FIN ");
        if ((flags & TCPFlags.RST) != 0) result.append("RST ");
        if ((flags & TCPFlags.PSH) != 0) result.append("PSH ");
        if ((flags & TCPFlags.URG) != 0) result.append("URG ");

        if (result.length() > 0) {
            result.setLength(result.length() - 1); // remove trailing space
        }
        
        return result.length() == 0 ? "none" : result.toString();
    }
}
