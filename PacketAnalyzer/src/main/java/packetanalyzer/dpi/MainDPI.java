package packetanalyzer.dpi;

public class MainDPI {
    private static void printUsage(String programName) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v2.0                            ║");
        System.out.println("║               Deep Packet Inspection System                   ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");
        System.out.println("Usage: java -jar " + programName + " <input.pcap> <output.pcap> [options]\n");
        System.out.println("Arguments:");
        System.out.println("  input.pcap     Input PCAP file (captured user traffic)");
        System.out.println("  output.pcap    Output PCAP file (filtered traffic to internet)\n");
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block packets from source IP");
        System.out.println("  --block-app <app>      Block application (e.g., YouTube, Facebook)");
        System.out.println("  --block-domain <dom>   Block domain (substring match)");
        System.out.println("  --lbs <n>              Number of load balancer threads (default: 2)");
        System.out.println("  --fps <n>              FP threads per LB (default: 2)\n");
        System.out.println("Examples:");
        System.out.println("  java -jar " + programName + " capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage("packet-analyzer.jar");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        DPIEngine.Config config = new DPIEngine.Config();
        java.util.List<String> blockIps = new java.util.ArrayList<>();
        java.util.List<String> blockApps = new java.util.ArrayList<>();
        java.util.List<String> blockDomains = new java.util.ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) {
                blockIps.add(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                blockApps.add(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                blockDomains.add(args[++i]);
            } else if (arg.equals("--lbs") && i + 1 < args.length) {
                config.numLbs = Integer.parseInt(args[++i]);
            } else if (arg.equals("--fps") && i + 1 < args.length) {
                config.fpsPerLb = Integer.parseInt(args[++i]);
            } else if (arg.equals("--help") || arg.equals("-h")) {
                printUsage("packet-analyzer.jar");
                System.exit(0);
            }
        }

        DPIEngine engine = new DPIEngine(config);

        for (String ip : blockIps) engine.blockIP(ip);
        for (String app : blockApps) engine.blockApp(app);
        for (String dom : blockDomains) engine.blockDomain(dom);

        if (!engine.process(inputFile, outputFile)) {
            System.exit(1);
        }

        System.out.println("\nOutput written to: " + outputFile);
    }
}
