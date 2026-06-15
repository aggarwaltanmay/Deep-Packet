package packetanalyzer.dpi;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

public class Types {

    public enum AppType {
        UNKNOWN(0),
        HTTP(1),
        HTTPS(2),
        DNS(3),
        TLS(4),
        QUIC(5),
        GOOGLE(6),
        FACEBOOK(7),
        YOUTUBE(8),
        TWITTER(9),
        INSTAGRAM(10),
        NETFLIX(11),
        AMAZON(12),
        MICROSOFT(13),
        APPLE(14),
        WHATSAPP(15),
        TELEGRAM(16),
        TIKTOK(17),
        SPOTIFY(18),
        ZOOM(19),
        DISCORD(20),
        GITHUB(21),
        CLOUDFLARE(22),
        APP_COUNT(23);

        private final int value;

        AppType(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

        public static AppType fromInt(int i) {
            for (AppType b : AppType.values()) {
                if (b.getValue() == i) { return b; }
            }
            return UNKNOWN;
        }
    }

    public static String appTypeToString(AppType type) {
        switch (type) {
            case UNKNOWN:    return "Unknown";
            case HTTP:       return "HTTP";
            case HTTPS:      return "HTTPS";
            case DNS:        return "DNS";
            case TLS:        return "TLS";
            case QUIC:       return "QUIC";
            case GOOGLE:     return "Google";
            case FACEBOOK:   return "Facebook";
            case YOUTUBE:    return "YouTube";
            case TWITTER:    return "Twitter/X";
            case INSTAGRAM:  return "Instagram";
            case NETFLIX:    return "Netflix";
            case AMAZON:     return "Amazon";
            case MICROSOFT:  return "Microsoft";
            case APPLE:      return "Apple";
            case WHATSAPP:   return "WhatsApp";
            case TELEGRAM:   return "Telegram";
            case TIKTOK:     return "TikTok";
            case SPOTIFY:    return "Spotify";
            case ZOOM:       return "Zoom";
            case DISCORD:    return "Discord";
            case GITHUB:     return "GitHub";
            case CLOUDFLARE: return "Cloudflare";
            default:         return "Unknown";
        }
    }

    public static AppType sniToAppType(String sni) {
        if (sni == null || sni.isEmpty()) return AppType.UNKNOWN;

        String lowerSni = sni.toLowerCase();

        if (lowerSni.contains("google") || lowerSni.contains("gstatic") ||
            lowerSni.contains("googleapis") || lowerSni.contains("ggpht") || lowerSni.contains("gvt1")) {
            return AppType.GOOGLE;
        }
        if (lowerSni.contains("youtube") || lowerSni.contains("ytimg") ||
            lowerSni.contains("youtu.be") || lowerSni.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }
        if (lowerSni.contains("facebook") || lowerSni.contains("fbcdn") ||
            lowerSni.contains("fb.com") || lowerSni.contains("fbsbx") || lowerSni.contains("meta.com")) {
            return AppType.FACEBOOK;
        }
        if (lowerSni.contains("instagram") || lowerSni.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }
        if (lowerSni.contains("whatsapp") || lowerSni.contains("wa.me")) {
            return AppType.WHATSAPP;
        }
        if (lowerSni.contains("twitter") || lowerSni.contains("twimg") ||
            lowerSni.contains("x.com") || lowerSni.contains("t.co")) {
            return AppType.TWITTER;
        }
        if (lowerSni.contains("netflix") || lowerSni.contains("nflxvideo") || lowerSni.contains("nflximg")) {
            return AppType.NETFLIX;
        }
        if (lowerSni.contains("amazon") || lowerSni.contains("amazonaws") ||
            lowerSni.contains("cloudfront") || lowerSni.contains("aws")) {
            return AppType.AMAZON;
        }
        if (lowerSni.contains("microsoft") || lowerSni.contains("msn.com") ||
            lowerSni.contains("office") || lowerSni.contains("azure") ||
            lowerSni.contains("live.com") || lowerSni.contains("outlook") || lowerSni.contains("bing")) {
            return AppType.MICROSOFT;
        }
        if (lowerSni.contains("apple") || lowerSni.contains("icloud") ||
            lowerSni.contains("mzstatic") || lowerSni.contains("itunes")) {
            return AppType.APPLE;
        }
        if (lowerSni.contains("telegram") || lowerSni.contains("t.me")) {
            return AppType.TELEGRAM;
        }
        if (lowerSni.contains("tiktok") || lowerSni.contains("tiktokcdn") ||
            lowerSni.contains("musical.ly") || lowerSni.contains("bytedance")) {
            return AppType.TIKTOK;
        }
        if (lowerSni.contains("spotify") || lowerSni.contains("scdn.co")) {
            return AppType.SPOTIFY;
        }
        if (lowerSni.contains("zoom")) {
            return AppType.ZOOM;
        }
        if (lowerSni.contains("discord") || lowerSni.contains("discordapp")) {
            return AppType.DISCORD;
        }
        if (lowerSni.contains("github") || lowerSni.contains("githubusercontent")) {
            return AppType.GITHUB;
        }
        if (lowerSni.contains("cloudflare") || lowerSni.contains("cf-")) {
            return AppType.CLOUDFLARE;
        }

        return AppType.HTTPS;
    }

    public enum ConnectionState {
        NEW,
        ESTABLISHED,
        CLASSIFIED,
        BLOCKED,
        CLOSED
    }

    public enum PacketAction {
        FORWARD,
        DROP,
        INSPECT,
        LOG_ONLY
    }

    public static class FiveTuple {
        public long srcIp;
        public long dstIp;
        public int srcPort;
        public int dstPort;
        public int protocol;

        public FiveTuple() {}

        public FiveTuple(long srcIp, long dstIp, int srcPort, int dstPort, int protocol) {
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.protocol = protocol;
        }

        public FiveTuple reverse() {
            return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            FiveTuple that = (FiveTuple) o;
            return srcIp == that.srcIp &&
                   dstIp == that.dstIp &&
                   srcPort == that.srcPort &&
                   dstPort == that.dstPort &&
                   protocol == that.protocol;
        }

        @Override
        public int hashCode() {
            int h = 0;
            h ^= Long.hashCode(srcIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= Long.hashCode(dstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= Integer.hashCode(srcPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= Integer.hashCode(dstPort) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= Integer.hashCode(protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }

        public String toString() {
            return formatIP(srcIp) + ":" + srcPort + " -> " + formatIP(dstIp) + ":" + dstPort +
                   " (" + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") + ")";
        }

        private String formatIP(long ip) {
            return ((ip >> 0) & 0xFF) + "." +
                   ((ip >> 8) & 0xFF) + "." +
                   ((ip >> 16) & 0xFF) + "." +
                   ((ip >> 24) & 0xFF);
        }
    }

    public static class Connection {
        public FiveTuple tuple;
        public ConnectionState state = ConnectionState.NEW;
        public AppType appType = AppType.UNKNOWN;
        public String sni = "";

        public long packetsIn = 0;
        public long packetsOut = 0;
        public long bytesIn = 0;
        public long bytesOut = 0;

        public long firstSeenMs;
        public long lastSeenMs;

        public PacketAction action = PacketAction.FORWARD;

        public boolean synSeen = false;
        public boolean synAckSeen = false;
        public boolean finSeen = false;
    }

    public static class PacketJob {
        public long packetId;
        public FiveTuple tuple;
        public byte[] data;
        public int ethOffset = 0;
        public int ipOffset = 0;
        public int transportOffset = 0;
        public int payloadOffset = 0;
        public int payloadLength = 0;
        public int tcpFlags = 0;
        
        public long tsSec;
        public long tsUsec;
    }

    public static class DPIStats {
        public final AtomicLong totalPackets = new AtomicLong(0);
        public final AtomicLong totalBytes = new AtomicLong(0);
        public final AtomicLong forwardedPackets = new AtomicLong(0);
        public final AtomicLong droppedPackets = new AtomicLong(0);
        public final AtomicLong tcpPackets = new AtomicLong(0);
        public final AtomicLong udpPackets = new AtomicLong(0);
        public final AtomicLong otherPackets = new AtomicLong(0);
        public final AtomicLong activeConnections = new AtomicLong(0);
    }
}
