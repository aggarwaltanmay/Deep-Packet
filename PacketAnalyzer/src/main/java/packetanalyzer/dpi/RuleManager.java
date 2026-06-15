package packetanalyzer.dpi;

import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.List;
import java.util.Set;
import java.util.Collections;

public class RuleManager {
    private final Set<Long> blockedIps = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<Types.AppType> blockedApps = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final List<String> blockedDomains = new CopyOnWriteArrayList<>();

    public void blockIP(String ipStr) {
        blockedIps.add(parseIP(ipStr));
        System.out.println("[Rules] Blocked IP: " + ipStr);
    }

    public void blockApp(String appStr) {
        for (Types.AppType type : Types.AppType.values()) {
            if (Types.appTypeToString(type).equalsIgnoreCase(appStr) || type.name().equalsIgnoreCase(appStr)) {
                blockedApps.add(type);
                System.out.println("[Rules] Blocked app: " + Types.appTypeToString(type));
                return;
            }
        }
        System.err.println("[Rules] Unknown app: " + appStr);
    }

    public void blockDomain(String domain) {
        blockedDomains.add(domain);
        System.out.println("[Rules] Blocked domain: " + domain);
    }

    public boolean isBlocked(long srcIp, Types.AppType app, String sni) {
        if (blockedIps.contains(srcIp)) return true;
        if (blockedApps.contains(app)) return true;
        
        if (sni != null && !sni.isEmpty()) {
            for (String dom : blockedDomains) {
                if (sni.contains(dom)) return true;
            }
        }
        return false;
    }

    private static long parseIP(String ip) {
        long result = 0;
        long octet = 0;
        int shift = 0;
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c == '.') {
                result |= (octet << shift);
                shift += 8;
                octet = 0;
            } else if (c >= '0' && c <= '9') {
                octet = octet * 10 + (c - '0');
            }
        }
        result |= (octet << shift);
        return result;
    }
}
