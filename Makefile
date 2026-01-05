CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -pthread
LDFLAGS = -lssl -lcrypto -lcurl

all: proxy_server stress_test

proxy_server: src/proxy_server.cpp
	$(CXX) $(CXXFLAGS) -o proxy_server src/proxy_server.cpp $(LDFLAGS)

stress_test: src/stress_test.cpp
	$(CXX) $(CXXFLAGS) -o stress_test src/stress_test.cpp $(LDFLAGS)

clean:
	rm -f proxy_server stress_test logs/proxy.log