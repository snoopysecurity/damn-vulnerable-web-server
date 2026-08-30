// logging_sink.h
//
// Pluggable destination for the access log plus the background worker
// that drains it. Installing/removing sinks is an admin operation
// (/admin/logging?output=file|syslog).
#ifndef DVWS_LOGGING_SINK_H
#define DVWS_LOGGING_SINK_H

#include <string>

// One log line on its way to a sink.
struct LogRecord {
    std::string timestamp;   // "YYYY-MM-DD HH:MM:SS"
    std::string message;
};

// A logging destination.
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void write(const LogRecord& record) = 0;
};

// Appends to the on-disk access log.
class FileLogSink : public LogSink {
public:
    void write(const LogRecord& record) override;
};

// Emits syslog-style lines on stderr.
class SyslogLogSink : public LogSink {
public:
    void write(const LogRecord& record) override;
};

// Currently installed sink (nullptr = standard synchronous logging).
LogSink* current_log_sink();

// Install a sink, replacing any previous one.
void install_log_sink(LogSink* sink);

// Queue one record for the background worker. The record remembers the
// sink that was installed at capture time.
void enqueue_log_record(const std::string& timestamp, const std::string& message);

#endif  // DVWS_LOGGING_SINK_H
