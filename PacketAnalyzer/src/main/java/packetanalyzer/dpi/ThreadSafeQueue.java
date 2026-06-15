package packetanalyzer.dpi;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class ThreadSafeQueue<T> {
    private final LinkedBlockingQueue<T> queue;
    private final AtomicBoolean shutdown = new AtomicBoolean(false);

    public ThreadSafeQueue(int maxSize) {
        this.queue = new LinkedBlockingQueue<>(maxSize);
    }

    public void push(T item) {
        try {
            while (!shutdown.get()) {
                if (queue.offer(item, 100, TimeUnit.MILLISECONDS)) {
                    return;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public boolean tryPush(T item) {
        if (shutdown.get()) return false;
        return queue.offer(item);
    }

    public T pop() {
        try {
            while (!shutdown.get() || !queue.isEmpty()) {
                T item = queue.poll(100, TimeUnit.MILLISECONDS);
                if (item != null) {
                    return item;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return null; // Will return null on shutdown if empty
    }

    public T popWithTimeout(long timeoutMillis) {
        try {
            return queue.poll(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    public boolean empty() {
        return queue.isEmpty();
    }

    public int size() {
        return queue.size();
    }

    public void shutdown() {
        shutdown.set(true);
    }

    public boolean isShutdown() {
        return shutdown.get();
    }
}
