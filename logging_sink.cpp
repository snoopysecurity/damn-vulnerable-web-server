// logging_sink.cpp
//
// The buffered async logging pipeline. Request threads capture the
// currently-installed sink pointer when they enqueue a record; a
// background worker flushes records to their captured sink no earlier
// than kFlushInterval after capture (a small batching delay keeps the
// disk writes amortized).
#include "logging_sink.h"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace {

// Records wait at least this long before the worker picks them up, so
// that bursts of requests are collapsed into fewer writes.
constexpr std::chrono::milliseconds kFlushInterval{250};

struct QueueEntry {
    LogRecord record;
    LogSink* sink;  // captured at enqueue time
    std::chrono::steady_clock::time_point enqueued_at;
};

std::mutex g_queue_mtx;
std::vector<QueueEntry> g_queue;

// NOTE: deliberately not synchronized with the queue or the worker.
// The admin thread swaps/deletes it while request threads read it.
LogSink* g_sink = nullptr;

void file_sink_write(const LogRecord& record) {
    std::ofstream log_file("/tmp/server.log", std::ios::app);
    if (!log_file) {
        fprintf(stderr, "FileLogSink: failed to open /tmp/server.log\n");
        return;
    }
    log_file << "[" << record.timestamp << "] " << record.message << "\n";
}

void syslog_sink_write(const LogRecord& record) {
    // Local syslog relay: priority header + timestamp + message on stderr,
    // the shape a real syslog() call would forward to the daemon.
    fprintf(stderr, "<134>dvws: [%s] %s\n",
            record.timestamp.c_str(), record.message.c_str());
}

void worker_loop() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        const auto now = std::chrono::steady_clock::now();
        std::vector<QueueEntry> due;
        {
            std::lock_guard<std::mutex> lock(g_queue_mtx);
            std::vector<QueueEntry> keep;
            keep.reserve(g_queue.size());
            for (auto& entry : g_queue) {
                if (now - entry.enqueued_at >= kFlushInterval) {
                    due.push_back(std::move(entry));
                } else {
                    keep.push_back(std::move(entry));
                }
            }
            g_queue.swap(keep);
        }

        for (const auto& entry : due) {
            // --- INTENTIONAL VULNERABILITY (CWE-416, use-after-free) ---
            // entry.sink may have been deleted by install_log_sink()
            // while this record sat in the queue. Nothing invalidated the
            // captured pointer, so this virtual call dispatches through
            // whatever now lives at that address (vtable pointer read
            // from freed memory when the chunk has been reclaimed).
            if (entry.sink != nullptr) {
                entry.sink->write(entry.record);
            }
        }
    }
}

void ensure_worker_started() {
    // Detached process-lifetime worker; the queue outlives any request.
    static std::thread worker(worker_loop);
    static bool detached = (worker.detach(), true);
    (void)detached;
}

}  // namespace

void FileLogSink::write(const LogRecord& record) {
    file_sink_write(record);
}

void SyslogLogSink::write(const LogRecord& record) {
    syslog_sink_write(record);
}

LogSink* current_log_sink() {
    return g_sink;
}

void install_log_sink(LogSink* sink) {
    // --- INTENTIONAL VULNERABILITY (CWE-416, use-after-free) ---
    // The outgoing sink is deleted immediately. Records already queued
    // for the async worker still hold the old pointer and will call
    // write() on it after the free. No synchronization with the worker,
    // no ownership hand-off of in-flight records.
    LogSink* old = g_sink;
    g_sink = sink;
    delete old;
}

void enqueue_log_record(const std::string& timestamp, const std::string& message) {
    ensure_worker_started();
    std::lock_guard<std::mutex> lock(g_queue_mtx);
    g_queue.push_back(QueueEntry{LogRecord{timestamp, message}, g_sink,
                                 std::chrono::steady_clock::now()});
}
