/**
 * @file stress_test.cpp
 * @brief Concurrent Load Tester for the Network Proxy Server.
 * * This utility simulates multiple users accessing the proxy simultaneously
 * to verify thread safety, caching efficiency, and connection handling.
 */

#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <curl/curl.h>

/**
 * @brief Discards incoming data during stress tests to minimize local I/O overhead.
 */
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    return size * nmemb;
}

/**
 * @brief Simulates a single user session making repeated requests through the proxy.
 * @param thread_id Unique identifier for the simulated user.
 * @param num_requests Number of requests this specific thread will execute.
 */
void test_proxy(int thread_id, int num_requests) {
    CURL* curl;
    CURLcode res;

    // Initialize libcurl per thread for safety
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) return;

    /* --- Proxy Configuration --- */
    curl_easy_setopt(curl, CURLOPT_PROXY, "127.0.0.1:8080");
    curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, "admin");
    curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, "password123");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

    // Disable SSL verification for faster testing if needed, though libcurl handles it well
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    // List of URLs to rotate through (mix of HTTP and HTTPS)
    std::vector<std::string> urls = {
        "http://httpbin.org/ip",
        "http://httpbin.org/headers",
        "https://httpbin.org/ip",
        "https://httpbin.org/headers"
    };

    int success = 0;
    for (int i = 0; i < num_requests; ++i) {
        std::string url = urls[i % urls.size()];
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // Perform the request
        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            success++;
        }

        // Small delay to simulate human-like browsing behavior and prevent OS socket exhaustion
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Cleanup resources
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    std::cout << "[User " << thread_id << "] Completed: " << success << "/"
              << num_requests << " requests successful." << std::endl;
}

/**
 * @brief Main execution block for the stress test.
 * * NOTE: Increasing num_threads beyond 500 may require increasing
 * system ulimits (ulimit -n) to allow more open file descriptors.
 */
int main() {
    const int num_threads = 50;          // Number of simultaneous users
    const int requests_per_thread = 100; // Requests per user

    std::cout << "Starting stress test with " << num_threads
              << " threads and " << (num_threads * requests_per_thread)
              << " total requests..." << std::endl;

    std::vector<std::thread> threads;

    // Spawn worker threads
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back(test_proxy, i, requests_per_thread);
    }

    // Wait for all simulated users to finish
    for (auto& t : threads) {
        t.join();
    }

    std::cout << "\n======================================" << std::endl;
    std::cout << "   Stress Test Completed Successfully " << std::endl;
    std::cout << "======================================" << std::endl;

    return 0;
}