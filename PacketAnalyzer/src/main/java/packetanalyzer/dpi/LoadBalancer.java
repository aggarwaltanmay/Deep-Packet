package packetanalyzer.dpi;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public class LoadBalancer implements Runnable {
    private final int lbId;
    private final List<FastPathProcessor> fps;
    private final int numFps;
    private final ThreadSafeQueue<Types.PacketJob> inputQueue;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread thread;
    private long dispatchedCount = 0;

    public LoadBalancer(int lbId, List<FastPathProcessor> fps) {
        this.lbId = lbId;
        this.fps = fps;
        this.numFps = fps.size();
        this.inputQueue = new ThreadSafeQueue<>(10000);
    }

    public void start() {
        if (running.compareAndSet(false, true)) {
            thread = new Thread(this, "LB-" + lbId);
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

    public long getDispatchedCount() {
        return dispatchedCount;
    }

    @Override
    public void run() {
        while (running.get()) {
            Types.PacketJob job = inputQueue.popWithTimeout(100);
            if (job == null) continue;

            int hash = job.tuple.hashCode();
            int fpIndex = Math.abs(hash) % numFps;

            fps.get(fpIndex).getInputQueue().push(job);
            dispatchedCount++;
        }
    }
}
