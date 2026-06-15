package packetanalyzer.dpi;

import packetanalyzer.PacketParser;
import packetanalyzer.PcapReader;
import packetanalyzer.models.ParsedPacket;
import packetanalyzer.models.Protocol;
import packetanalyzer.models.RawPacket;

import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

public class DPIEngine {
    public static class Config {
        public int numLbs = 2;
        public int fpsPerLb = 2;
    }

    private final Config config;
    private final RuleManager ruleManager;
    private final Types.DPIStats stats;
    private final ThreadSafeQueue<Types.PacketJob> outputQueue;

    private final List<FastPathProcessor> fps = new ArrayList<>();
    private final List<LoadBalancer> lbs = new ArrayList<>();

    public DPIEngine(Config config) {
        this.config = config;
        this.ruleManager = new RuleManager();
        this.stats = new Types.DPIStats();
        this.outputQueue = new ThreadSafeQueue<>(10000);

        int totalFps = config.numLbs * config.fpsPerLb;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║              DPI ENGINE v2.0 (Multi-threaded)                 ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d     ║\n", config.numLbs, config.fpsPerLb, totalFps);
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");

        for (int i = 0; i < totalFps; i++) {
            fps.add(new FastPathProcessor(i, ruleManager, stats, outputQueue));
        }

        for (int lb = 0; lb < config.numLbs; lb++) {
            List<FastPathProcessor> lbFps = new ArrayList<>();
            int start = lb * config.fpsPerLb;
            for (int i = 0; i < config.fpsPerLb; i++) {
                lbFps.add(fps.get(start + i));
            }
            lbs.add(new LoadBalancer(lb, lbFps));
        }
    }

    public void blockIP(String ip) { ruleManager.blockIP(ip); }
    public void blockApp(String app) { ruleManager.blockApp(app); }
    public void blockDomain(String dom) { ruleManager.blockDomain(dom); }

    public boolean process(String inputFile, String outputFile) {
        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) return false;

        DataOutputStream outStream = null;
        try {
            outStream = new DataOutputStream(new FileOutputStream(outputFile));
            // Global Header mapping - reading original raw header was not stored in PcapReader, 
            // We write a default native pcap header
            outStream.writeInt(0xa1b2c3d4);
            outStream.writeShort(2);
            outStream.writeShort(4);
            outStream.writeInt(0);
            outStream.writeInt(0);
            outStream.writeInt(65535); // snaplen
            outStream.writeInt(1); // ethernet
        } catch (IOException e) {
            System.err.println("Cannot open output file");
            return false;
        }

        for (FastPathProcessor fp : fps) fp.start();
        for (LoadBalancer lb : lbs) lb.start();

        AtomicBoolean outputRunning = new AtomicBoolean(true);
        DataOutputStream finalOutStream = outStream;
        Thread outputThread = new Thread(() -> {
            try {
                while (outputRunning.get() || !outputQueue.empty()) {
                    Types.PacketJob job = outputQueue.popWithTimeout(50);
                    if (job == null) continue;

                    finalOutStream.writeInt((int) job.tsSec);
                    finalOutStream.writeInt((int) job.tsUsec);
                    finalOutStream.writeInt(job.data.length);
                    finalOutStream.writeInt(job.data.length);
                    finalOutStream.write(job.data);
                }
            } catch (IOException e) {
                System.err.println("Error writing to output file");
            }
        });
        outputThread.start();

        System.out.println("[Reader] Processing packets...");
        RawPacket raw = new RawPacket();
        ParsedPacket parsed = new ParsedPacket();
        long pktId = 0;

        while (reader.readNextPacket(raw)) {
            if (!PacketParser.parse(raw, parsed)) continue;
            if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

            Types.PacketJob job = new Types.PacketJob();
            job.packetId = pktId++;
            job.tsSec = raw.tsSec;
            job.tsUsec = raw.tsUsec;
            job.tcpFlags = parsed.tcpFlags;
            job.data = raw.data.clone();

            job.tuple = new Types.FiveTuple(
                parseIP(parsed.srcIp),
                parseIP(parsed.destIp),
                parsed.srcPort,
                parsed.destPort,
                parsed.protocol
            );

            job.payloadOffset = 14; 
            if (job.data.length > 14) {
                int ipIhl = job.data[14] & 0x0F;
                job.payloadOffset += ipIhl * 4;

                if (parsed.hasTcp && job.payloadOffset + 12 < job.data.length) {
                    int tcpOff = (job.data[job.payloadOffset + 12] >> 4) & 0x0F;
                    job.payloadOffset += tcpOff * 4;
                } else if (parsed.hasUdp) {
                    job.payloadOffset += 8;
                }

                if (job.payloadOffset < job.data.length) {
                    job.payloadLength = job.data.length - job.payloadOffset;
                } else {
                    job.payloadLength = 0;
                }
            }

            stats.totalPackets.incrementAndGet();
            stats.totalBytes.addAndGet(job.data.length);
            if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
            else if (parsed.hasUdp) stats.udpPackets.incrementAndGet();

            int lbIdx = Math.abs(job.tuple.hashCode()) % lbs.size();
            lbs.get(lbIdx).getInputQueue().push(job);
        }

        System.out.println("[Reader] Done reading " + pktId + " packets");
        reader.close();

        try {
            Thread.sleep(500); // Wait for queues to drain
        } catch (InterruptedException ignored) {}

        for (LoadBalancer lb : lbs) lb.stop();
        for (FastPathProcessor fp : fps) fp.stop();

        outputRunning.set(false);
        outputQueue.shutdown();
        try {
            outputThread.join();
            if (finalOutStream != null) finalOutStream.close();
        } catch (Exception ignored) {}

        printReport();
        return true;
    }

    private long parseIP(String ip) {
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

    private void printReport() {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                        ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Total Packets:      %12d                           ║\n", stats.totalPackets.get());
        System.out.printf("║ Total Bytes:        %12d                           ║\n", stats.totalBytes.get());
        System.out.printf("║ TCP Packets:        %12d                           ║\n", stats.tcpPackets.get());
        System.out.printf("║ UDP Packets:        %12d                           ║\n", stats.udpPackets.get());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Forwarded:          %12d                           ║\n", stats.forwardedPackets.get());
        System.out.printf("║ Dropped:            %12d                           ║\n", stats.droppedPackets.get());
        
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ THREAD STATISTICS                                             ║");
        for (int i = 0; i < lbs.size(); i++) {
            System.out.printf("║   LB%-2d dispatched:   %12d                           ║\n", i, lbs.get(i).getDispatchedCount());
        }
        for (int i = 0; i < fps.size(); i++) {
            System.out.printf("║   FP%-2d processed:    %12d                           ║\n", i, fps.get(i).getProcessedCount());
        }
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }
}
