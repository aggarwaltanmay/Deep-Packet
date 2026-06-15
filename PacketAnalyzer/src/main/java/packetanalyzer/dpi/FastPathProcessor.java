package packetanalyzer.dpi;

import packetanalyzer.models.Protocol;

import java.util.concurrent.atomic.AtomicBoolean;

public class FastPathProcessor implements Runnable {
    private final int fpId;
    private final RuleManager ruleManager;
    private final Types.DPIStats stats;
    private final ThreadSafeQueue<Types.PacketJob> inputQueue;
    private final ThreadSafeQueue<Types.PacketJob> outputQueue;
    private final ConnectionTracker connTracker;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;
    private long processedCount = 0;

    public FastPathProcessor(int fpId, RuleManager ruleManager, Types.DPIStats stats, ThreadSafeQueue<Types.PacketJob> outputQueue) {
        this.fpId = fpId;
        this.ruleManager = ruleManager;
        this.stats = stats;
        this.inputQueue = new ThreadSafeQueue<>(10000);
        this.outputQueue = outputQueue;
        this.connTracker = new ConnectionTracker(fpId);
    }

    public void start() {
        if (running.compareAndSet(false, true)) {
            thread = new Thread(this, "FP-" + fpId);
            thread.start();
        }
    }

    public void stop() {
        if (running.compareAndSet(true, false)) {
            inputQueue.shutdown();
            if (thread != null) {
                try {
                    thread.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    public ThreadSafeQueue<Types.PacketJob> getInputQueue() {
        return inputQueue;
    }

    public long getProcessedCount() {
        return processedCount;
    }

    @Override
    public void run() {
        while (running.get()) {
            Types.PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null) continue;

            processedCount++;
            Types.Connection conn = connTracker.getOrCreateConnection(job.tuple);

            if (conn.packetsIn == 0 && conn.packetsOut == 0) {
                // First packet
            }
            
            conn.packetsIn++;
            conn.bytesIn += job.data.length;

            if (conn.state != Types.ConnectionState.CLASSIFIED) {
                classifyFlow(job, conn);
            }

            if (conn.state != Types.ConnectionState.BLOCKED) {
                boolean isBlocked = ruleManager.isBlocked(job.tuple.srcIp, conn.appType, conn.sni);
                if (isBlocked) {
                    conn.state = Types.ConnectionState.BLOCKED;
                    conn.action = Types.PacketAction.DROP;
                }
            }

            if (conn.state == Types.ConnectionState.BLOCKED) {
                stats.droppedPackets.incrementAndGet();
            } else {
                stats.forwardedPackets.incrementAndGet();
                if (outputQueue != null) {
                    outputQueue.push(job);
                }
            }
        }
    }

    private void classifyFlow(Types.PacketJob job, Types.Connection conn) {
        if (job.tuple.dstPort == 443 && job.payloadLength > 5) {
            SNIExtractor.extractTLS(job.data, job.data.length).ifPresent(sni -> {
                conn.sni = sni;
                conn.appType = Types.sniToAppType(sni);
                conn.state = Types.ConnectionState.CLASSIFIED;
            });
            if (conn.state == Types.ConnectionState.CLASSIFIED) return;
        }

        if (job.tuple.dstPort == 80 && job.payloadLength > 10) {
            SNIExtractor.extractHTTPHost(job.data, job.data.length).ifPresent(host -> {
                conn.sni = host;
                conn.appType = Types.sniToAppType(host);
                conn.state = Types.ConnectionState.CLASSIFIED;
            });
            if (conn.state == Types.ConnectionState.CLASSIFIED) return;
        }

        if (job.tuple.dstPort == 53 || job.tuple.srcPort == 53) {
            conn.appType = Types.AppType.DNS;
            conn.state = Types.ConnectionState.CLASSIFIED;
            return;
        }

        if (job.tuple.dstPort == 443) {
            conn.appType = Types.AppType.HTTPS;
        } else if (job.tuple.dstPort == 80) {
            conn.appType = Types.AppType.HTTP;
        }
    }
}
