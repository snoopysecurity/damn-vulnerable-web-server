// thread_pool.h
//
// Minimal fixed-size thread pool for the accept loop. Multiple workshop
// students can now poke the server simultaneously. Note that this
// *broadens* the attack surface of the intentional heap bugs: concurrent
// requests give attackers better heap-grooming primitives (a feature,
// not a bug, in a teaching context).
#ifndef DVWS_THREAD_POOL_H
#define DVWS_THREAD_POOL_H

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class ThreadPool {
public:
    explicit ThreadPool(size_t n_workers);
    ~ThreadPool();

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    // Submit a task. Never blocks; the queue is unbounded.
    void submit(std::function<void()> task);

private:
    void worker_loop();

    std::vector<std::thread>          workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex                        mtx_;
    std::condition_variable           cv_;
    bool                              shutdown_ = false;
};

#endif
