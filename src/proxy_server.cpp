/**
 * @file proxy_server.cpp
 * @brief A multi-threaded HTTP/HTTPS Proxy Server with LRU Caching and Authentication.
 * * This server implements a thread-per-connection model, basic proxy authentication,
 * domain-based filtering, and a Least Recently Used (LRU) cache for GET requests.
 */

#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <memory>
#include <atomic>
#include <regex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <algorithm>
#include <list>
#include <ctime>

/**
 * @class CacheManager
 * @brief Thread-safe LRU Cache to store and retrieve HTTP responses.
 */
class CacheManager {
private:
    struct CacheEntry {
        std::string data;
        std::time_t timestamp;
    };
    size_t max_items;
    // Map for O(1) access; List for tracking usage order
    std::unordered_map<std::string, std::pair<std::string, std::list<std::string>::iterator>> cache_map;
    std::list<std::string> lru_list;
    std::mutex mtx;

public:
    explicit CacheManager(size_t size = 50) : max_items(size) {}

    /**
     * @brief Retrieves an item from cache and updates its position in the LRU list.
     */
    bool get(const std::string& key, std::string& val) {
        std::lock_guard<std::mutex> lock(mtx);
        if (cache_map.find(key) == cache_map.end()) return false;

        lru_list.erase(cache_map[key].second);
        lru_list.push_front(key);
        cache_map[key].second = lru_list.begin();
        val = cache_map[key].first;
        return true;
    }

    /**
     * @brief Inserts a new item into cache, evicting the least recently used if full.
     */
    void put(const std::string& key, const std::string& val) {
        std::lock_guard<std::mutex> lock(mtx);
        if (cache_map.size() >= max_items) {
            cache_map.erase(lru_list.back());
            lru_list.pop_back();
        }
        lru_list.push_front(key);
        cache_map[key] = {val, lru_list.begin()};
    }
};

/**
 * @class Logger
 * @brief Thread-safe logging utility for tracking requests and server status.
 */
class Logger {
private:
    std::mutex log_mutex;
    std::ofstream log_file;
    std::atomic<uint64_t> count{0};

public:
    explicit Logger(const std::string& filename) {
        log_file.open(filename, std::ios::app);
    }

    void log(const std::string& msg) {
        std::lock_guard<std::mutex> lock(log_mutex);
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::stringstream ss;
        ss << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S") << " | " << msg << "\n";
        log_file << ss.str();
        log_file.flush();
        std::cout << ss.str();
    }

    void log_req(const std::string& ip, const std::string& m, const std::string& h, bool a) {
        count++;
        log("REQ #" + std::to_string(count) + " | " + ip + " | " + m + " | " + h + " | " + (a ? "ALLOWED" : "BLOCKED"));
    }
};

/**
 * @class SiteFilter
 * @brief Handles domain-based blacklisting with support for suffix matching.
 */
class SiteFilter {
private:
    std::set<std::string> blocked;
    std::mutex mtx;

public:
    void load(const std::string& file) {
        std::lock_guard<std::mutex> lock(mtx);
        blocked.clear();
        std::ifstream f(file);
        std::string line;
        while (std::getline(f, line)) {
            // Trim whitespace and newlines
            line.erase(0, line.find_first_not_of(" \r\n\t"));
            line.erase(line.find_last_not_of(" \r\n\t") + 1);
            if (!line.empty()) {
                std::transform(line.begin(), line.end(), line.begin(), ::tolower);
                blocked.insert(line);
            }
        }
    }

    bool is_blocked(const std::string& host) {
        std::lock_guard<std::mutex> lock(mtx);
        std::string h = host;
        std::transform(h.begin(), h.end(), h.begin(), ::tolower);

        if (blocked.count(h)) return true;
        // Suffix matching (e.g., blocking example.com also blocks sub.example.com)
        for (auto& s : blocked) {
            if (h.size() > s.size() && h.substr(h.size() - s.size() - 1) == "." + s) return true;
        }
        return false;
    }
};

/**
 * @class AuthManager
 * @brief Manages proxy user credentials using hashed passwords.
 */
class AuthManager {
private:
    std::unordered_map<std::string, std::string> users;
    std::mutex mtx;

public:
    void add(const std::string& u, const std::string& p) {
        std::lock_guard<std::mutex> lock(mtx);
        users[u] = std::to_string(std::hash<std::string>{}(p));
    }

    bool verify(const std::string& u, const std::string& p) {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = users.find(u);
        return it != users.end() && it->second == std::to_string(std::hash<std::string>{}(p));
    }
};

/**
 * @class ProxyConnection
 * @brief Encapsulates the lifecycle of a single client-to-server proxy request.
 */
class ProxyConnection {
private:
    int c_fd;
    Logger& logger;
    SiteFilter& filter;
    AuthManager& auth;
    CacheManager& cache;
    std::string c_ip;

    /**
     * @brief Reads bytes from the socket until the HTTP header terminator (\r\n\r\n) is found.
     */
    std::string read_headers() {
        std::string h; char b[1];
        while (h.find("\r\n\r\n") == std::string::npos) {
            if (recv(c_fd, b, 1, 0) <= 0) break;
            h += b[0];
            if (h.size() > 8192) break; // Prevent header overflow attacks
        }
        return h;
    }

    std::string base64_decode(const std::string& in) {
        static const std::string cl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out; int v = 0, vb = -8;
        for (unsigned char c : in) {
            auto idx = cl.find(c);
            if (idx == std::string::npos) continue;
            v = (v << 6) + idx; vb += 6;
            if (vb >= 0) { out.push_back(char((v >> vb) & 0xFF)); vb -= 8; }
        }
        return out;
    }

public:
    ProxyConnection(int fd, Logger& l, SiteFilter& f, AuthManager& a, CacheManager& ch)
        : c_fd(fd), logger(l), filter(f), auth(a), cache(ch) {
        sockaddr_in ad; socklen_t ln = sizeof(ad);
        getpeername(fd, (sockaddr*)&ad, &ln);
        c_ip = inet_ntoa(ad.sin_addr);
    }

    /**
     * @brief Core logic for processing, authenticating, filtering, and relaying traffic.
     */
    void process() {
        std::string req = read_headers();
        if (req.empty()) { close(c_fd); return; }

        // Step 1: Proxy Authentication Check
        std::regex ar(R"(Proxy-Authorization: Basic ([^\r\n]+)\r)");
        std::smatch am;
        if (std::regex_search(req, am, ar)) {
            std::string d = base64_decode(am[1].str());
            size_t cl = d.find(':');
            if (cl == std::string::npos || !auth.verify(d.substr(0, cl), d.substr(cl + 1))) {
                const char* m = "HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n";
                send(c_fd, m, strlen(m), 0); close(c_fd); return;
            }
        } else {
            const char* m = "HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n";
            send(c_fd, m, strlen(m), 0); close(c_fd); return;
        }

        // Step 2: Request Parsing (Method, Host, Port, Path)
        std::regex rr(R"((\w+) (https?://)?([^/:\s]+)(:(\d+))?([^ \r\n]*) HTTP/[\d.]+\r)");
        std::smatch m;
        if (!std::regex_search(req, m, rr)) { close(c_fd); return; }
        std::string method = m[1].str(), host = m[3].str();
        int port = m[5].matched ? std::stoi(m[5].str()) : (method == "CONNECT" ? 443 : 80);
        std::string path = (m[6].matched && !m[6].str().empty()) ? m[6].str() : "/";

        // Step 3: Domain Filtering Logic
        if (filter.is_blocked(host)) {
            const char* msg = "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden";
            send(c_fd, msg, strlen(msg), 0); logger.log_req(c_ip, method, host, false);
            close(c_fd); return;
        }
        logger.log_req(c_ip, method, host, true);

        // Step 4: LRU Cache Lookup (Only for HTTP GET)
        std::string cached_val;
        if (method == "GET" && cache.get(host + path, cached_val)) {
            send(c_fd, cached_val.c_str(), cached_val.size(), 0);
            close(c_fd); return;
        }

        // Step 5: Establishing Connection to Target Server
        struct addrinfo hints, *res; memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) { close(c_fd); return; }
        int t_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (connect(t_fd, res->ai_addr, res->ai_addrlen) < 0) {
            close(c_fd); close(t_fd); freeaddrinfo(res); return;
        }
        freeaddrinfo(res);

        // Step 6: Relay Request or Handle HTTPS Tunneling
        if (method == "CONNECT") {
            const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(c_fd, ok, strlen(ok), 0);
        } else {
            std::string relay = method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
            send(t_fd, relay.c_str(), relay.size(), 0);
        }

        // Step 7: Bidirectional Data Tunneling using select()
        fd_set fds; char buf[8192];
        while (true) {
            FD_ZERO(&fds); FD_SET(c_fd, &fds); FD_SET(t_fd, &fds);
            if (select(std::max(c_fd, t_fd) + 1, &fds, NULL, NULL, NULL) <= 0) break;

            if (FD_ISSET(c_fd, &fds)) {
                ssize_t n = recv(c_fd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                send(t_fd, buf, n, 0);
            }
            if (FD_ISSET(t_fd, &fds)) {
                ssize_t n = recv(t_fd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                send(c_fd, buf, n, 0);
                // Simple cache population for HTTP responses
                if (method == "GET") cache.put(host + path, std::string(buf, n));
            }
        }
        close(t_fd); close(c_fd);
    }
};

/**
 * @class ProxyServer
 * @brief Main server class that initializes components and listens for connections.
 */
class ProxyServer {
private:
    int s_fd; Logger logger; SiteFilter filter; AuthManager auth; CacheManager cache;
public:
    explicit ProxyServer(int p) : logger("logs/proxy.log") {
        auth.add("admin", "password123");
        filter.load("config/blocked.txt");

        s_fd = socket(AF_INET, SOCK_STREAM, 0);
        int o = 1; setsockopt(s_fd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));

        sockaddr_in a = {AF_INET, htons(p), {INADDR_ANY}};
        if (bind(s_fd, (sockaddr*)&a, sizeof(a)) < 0) {
            logger.log("Error: Failed to bind to port " + std::to_string(p));
            exit(1);
        }
        listen(s_fd, 100);
        logger.log("Proxy started on port " + std::to_string(p));
    }

    /**
     * @brief Accepts incoming connections and dispatches them to detached threads.
     */
    void run() {
        while (true) {
            int c_fd = accept(s_fd, NULL, NULL);
            if (c_fd >= 0) {
                std::thread([this, c_fd]() {
                    ProxyConnection(c_fd, logger, filter, auth, cache).process();
                }).detach();
            }
        }
    }
};

int main() {
    ProxyServer(8080).run();
    return 0;
}