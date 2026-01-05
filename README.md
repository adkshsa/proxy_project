Markdown

# Custom Network Proxy Server

A high-performance C++ forward proxy server supporting HTTP/HTTPS, multi-threaded concurrency, LRU caching, and rule-based filtering.

## 📁 Project Structure
- **src/**: Source code for the Proxy Server and Stress Test.
- **config/**: Configuration files (blocked domains).
- **docs/**: Design documentation.
- **logs/**: Traffic and event logs.
## 📽️Project Video
[🎥 Project Video featuring usage on system browser](https://drive.google.com/file/d/1gru-2m9jZVjOg_27GFOmp9l1L7Ef5oW_/view?usp=sharing)

[🎥 Project Video featuring usage with curl commands](https://drive.google.com/file/d/1IKgT_vWwIn1T2cipGGBQHlShZ8PrcYLo/view?usp=sharing)

## 🛠 Compilation
Ensure you have `g++`, `openssl`, and `libcurl` installed. Run the following command in the root directory:

```bash

make
```
🚀 Usage
1. Start the Proxy Server
```bash

./proxy_server
```
The server will start listening on port 8080.

2. Run a Request (Manual Test)
Use the built-in credentials to test the proxy:

Username: admin

Password: password123

```bash

curl -v -x [http://admin:password123@127.0.0.1:8080](http://admin:password123@127.0.0.1:8080) [http://httpbin.org/ip](http://httpbin.org/ip)
```
3. Verify Filtering
Test a site listed in config/blocked.txt (e.g., facebook.com) to verify the 403 Forbidden response:

```bash

curl -I -x [http://admin:password123@127.0.0.1:8080](http://admin:password123@127.0.0.1:8080) [http://facebook.com](http://facebook.com)
```
4. Stress Testing
To simulate 50 concurrent users making 100 requests each:

```bash

./stress_test
```
📊 Features Implemented
Concurrency: Thread-per-connection model.

HTTPS: Transparent tunneling via the CONNECT method.

Security: Basic Proxy Authentication (Base64).

Caching: LRU (Least Recently Used) cache for optimized GET requests.

Filtering: Domain suffix-matching for blacklisting.


***

### One last safety check
Before you finish, make sure your **`logs`** folder exists. If it doesn't, the server might crash when trying to create the log file. You can ensure it exists by running this in your terminal:

```bash

mkdir -p logs

