#include <chrono>
#include <cstring>
#include <expected>
#include <format>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>

namespace fintech::tls_client {

enum class ClientError {
    NetworkResolutionFailed,
    SocketCreationFailed,
    ConnectionFailed,
    SslContextCreationFailed,
    SslCreationFailed,
    SslConnectionFailed,
    CertificateValidationFailed,
    HandshakeTimeout,
    SendFailed,
    ReceiveFailed,
    InvalidResponse,
    TimeoutExpired
};

class ErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override {
        return "fintech_tls_client";
    }
    
    std::string message(int ev) const override {
        switch (static_cast<ClientError>(ev)) {
            case ClientError::NetworkResolutionFailed:
                return "Failed to resolve hostname";
            case ClientError::SocketCreationFailed:
                return "Failed to create socket";
            case ClientError::ConnectionFailed:
                return "Failed to connect to server";
            case ClientError::SslContextCreationFailed:
                return "Failed to create SSL context";
            case ClientError::SslCreationFailed:
                return "Failed to create SSL connection";
            case ClientError::SslConnectionFailed:
                return "SSL connection failed";
            case ClientError::CertificateValidationFailed:
                return "Server certificate validation failed";
            case ClientError::HandshakeTimeout:
                return "TLS handshake timed out";
            case ClientError::SendFailed:
                return "Failed to send data";
            case ClientError::ReceiveFailed:
                return "Failed to receive data";
            case ClientError::InvalidResponse:
                return "Invalid HTTP response received";
            case ClientError::TimeoutExpired:
                return "Operation timed out";
            default:
                return "Unknown error";
        }
    }
};

const ErrorCategory& error_category() {
    static ErrorCategory instance;
    return instance;
}

std::error_code make_error_code(ClientError e) {
    return {static_cast<int>(e), error_category()};
}

} // namespace fintech::tls_client

// Enable std::error_code integration
template<>
struct std::is_error_code_enum<fintech::tls_client::ClientError> : true_type {};

namespace fintech::tls_client {

struct HttpResponse {
    int status_code;
    std::string status_message;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::chrono::milliseconds latency;
};

class SecureTlsClient {
private:
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ssl_ctx_;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl_;
    int socket_fd_{-1};
    std::string hostname_;
    int port_;
    
    static constexpr int TIMEOUT_SECONDS = 10;
    static constexpr size_t BUFFER_SIZE = 8192;

public:
    SecureTlsClient() : ssl_ctx_(nullptr, &SSL_CTX_free), ssl_(nullptr, &SSL_free) {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    }
    
    ~SecureTlsClient() {
        cleanup();
    }
    
    SecureTlsClient(const SecureTlsClient&) = delete;
    SecureTlsClient& operator=(const SecureTlsClient&) = delete;
    
    SecureTlsClient(SecureTlsClient&& other) noexcept 
        : ssl_ctx_(std::move(other.ssl_ctx_))
        , ssl_(std::move(other.ssl_))
        , socket_fd_(std::exchange(other.socket_fd_, -1))
        , hostname_(std::move(other.hostname_))
        , port_(other.port_) {}

    SecureTlsClient& operator=(SecureTlsClient&& other) noexcept {
        if (this != &other) {
            cleanup();
            ssl_ctx_ = std::move(other.ssl_ctx_);
            ssl_ = std::move(other.ssl_);
            socket_fd_ = std::exchange(other.socket_fd_, -1);
            hostname_ = std::move(other.hostname_);
            port_ = other.port_;
        }
        return *this;
    }

    std::expected<void, std::error_code> connect(std::string_view hostname, int port) {
        hostname_ = hostname;
        port_ = port;
        
        // Create SSL context
        ssl_ctx_.reset(SSL_CTX_new(TLS_client_method()));
        if (!ssl_ctx_) {
            return std::unexpected(make_error_code(ClientError::SslContextCreationFailed));
        }
        
        // Configure TLS 1.3 minimum
        SSL_CTX_set_min_proto_version(ssl_ctx_.get(), TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ssl_ctx_.get(), TLS1_3_VERSION);
        
        // Load system certificate store
        if (SSL_CTX_set_default_verify_paths(ssl_ctx_.get()) != 1) {
            return std::unexpected(make_error_code(ClientError::CertificateValidationFailed));
        }
        
        // Enable certificate verification
        SSL_CTX_set_verify(ssl_ctx_.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_verify_depth(ssl_ctx_.get(), 9);
        
        // Resolve hostname
        auto resolve_result = resolve_hostname(hostname, port);
        if (!resolve_result.has_value()) {
            return std::unexpected(resolve_result.error());
        }
        
        // Create and connect socket
        auto connect_result = create_and_connect_socket(*resolve_result);
        if (!connect_result.has_value()) {
            return std::unexpected(connect_result.error());
        }
        
        // Setup SSL connection
        ssl_.reset(SSL_new(ssl_ctx_.get()));
        if (!ssl_) {
            return std::unexpected(make_error_code(ClientError::SslCreationFailed));
        }
        
        // Enable SNI
        if (SSL_set_tlsext_host_name(ssl_.get(), hostname_.c_str()) != 1) {
            return std::unexpected(make_error_code(ClientError::SslConnectionFailed));
        }
        
        // Set hostname for certificate verification
        if (SSL_set1_host(ssl_.get(), hostname_.c_str()) != 1) {
            return std::unexpected(make_error_code(ClientError::CertificateValidationFailed));
        }
        
        SSL_set_fd(ssl_.get(), socket_fd_);
        
        // Perform TLS handshake with timeout
        auto handshake_start = std::chrono::steady_clock::now();
        int ssl_result;
        
        while ((ssl_result = SSL_connect(ssl_.get())) != 1) {
            auto now = std::chrono::steady_clock::now();
            if (now - handshake_start > std::chrono::seconds(TIMEOUT_SECONDS)) {
                return std::unexpected(make_error_code(ClientError::HandshakeTimeout));
            }
            
            int ssl_error = SSL_get_error(ssl_.get(), ssl_result);
            if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE) {
                std::println(stderr, "SSL handshake failed: {}", ERR_error_string(ERR_get_error(), nullptr));
                return std::unexpected(make_error_code(ClientError::SslConnectionFailed));
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        // Verify certificate
        long verify_result = SSL_get_verify_result(ssl_.get());
        if (verify_result != X509_V_OK) {
            std::println(stderr, "Certificate verification failed: {}", X509_verify_cert_error_string(verify_result));
            return std::unexpected(make_error_code(ClientError::CertificateValidationFailed));
        }
        
        std::println("TLS 1.3 connection established successfully to {}:{}", hostname_, port_);
        return {};
    }
    
    std::expected<HttpResponse, std::error_code> send_get_request(std::string_view path) {
        auto start_time = std::chrono::steady_clock::now();
        
        // Construct HTTP/1.1 GET request
        std::string request = std::format(
            "GET {} HTTP/1.1\r\n"
            "Host: {}\r\n"
            "User-Agent: Fintech-TLS-Client/1.0\r\n"
            "Accept: application/json\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, hostname_
        );
        
        // Send request
        int bytes_sent = SSL_write(ssl_.get(), request.c_str(), static_cast<int>(request.length()));
        if (bytes_sent <= 0) {
            return std::unexpected(make_error_code(ClientError::SendFailed));
        }
        
        std::println("Sent HTTP GET request to {}", path);
        
        // Receive response
        std::string response;
        std::vector<char> buffer(BUFFER_SIZE);
        
        while (true) {
            int bytes_received = SSL_read(ssl_.get(), buffer.data(), static_cast<int>(buffer.size()));
            if (bytes_received <= 0) {
                int ssl_error = SSL_get_error(ssl_.get(), bytes_received);
                if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                    break; // Connection closed cleanly
                }
                return std::unexpected(make_error_code(ClientError::ReceiveFailed));
            }
            response.append(buffer.data(), bytes_received);
        }
        
        auto end_time = std::chrono::steady_clock::now();
        auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        // Parse HTTP response
        return parse_http_response(response, latency);
    }

private:
    struct AddressInfo {
        struct addrinfo* info;
        
        explicit AddressInfo(struct addrinfo* addr) : info(addr) {}
        ~AddressInfo() { if (info) freeaddrinfo(info); }
        
        AddressInfo(const AddressInfo&) = delete;
        AddressInfo& operator=(const AddressInfo&) = delete;
        
        AddressInfo(AddressInfo&& other) noexcept : info(std::exchange(other.info, nullptr)) {}
    };
    
    std::expected<AddressInfo, std::error_code> resolve_hostname(std::string_view hostname, int port) {
        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        
        struct addrinfo* result = nullptr;
        std::string port_str = std::to_string(port);
        std::string hostname_str{hostname}; // Ensure null termination
        
        int status = getaddrinfo(hostname_str.c_str(), port_str.c_str(), &hints, &result);
        if (status != 0) {
            std::println(stderr, "getaddrinfo failed: {}", gai_strerror(status));
            return std::unexpected(make_error_code(ClientError::NetworkResolutionFailed));
        }
        
        return AddressInfo{result};
    }
    
    std::expected<void, std::error_code> create_and_connect_socket(const AddressInfo& addr_info) {
        for (struct addrinfo* addr = addr_info.info; addr != nullptr; addr = addr->ai_next) {
            socket_fd_ = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
            if (socket_fd_ == -1) {
                continue;
            }
            
            // Set socket timeout
            struct timeval timeout{};
            timeout.tv_sec = TIMEOUT_SECONDS;
            timeout.tv_usec = 0;
            
            setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            
            if (::connect(socket_fd_, addr->ai_addr, addr->ai_addrlen) == 0) {
                std::println("TCP connection established to {}:{}", hostname_, port_);
                return {};
            }
            
            close(socket_fd_);
            socket_fd_ = -1;
        }
        
        return std::unexpected(make_error_code(ClientError::ConnectionFailed));
    }
    
    std::expected<std::pair<int, std::string>, std::error_code> parse_status_line(const std::string& headers) {
        size_t first_line_end = headers.find("\r\n");
        if (first_line_end == std::string::npos) {
            return std::unexpected(make_error_code(ClientError::InvalidResponse));
        }
        
        std::string status_line = headers.substr(0, first_line_end);
        size_t first_space = status_line.find(' ');
        size_t second_space = status_line.find(' ', first_space + 1);
        
        if (first_space == std::string::npos || second_space == std::string::npos) {
            return std::unexpected(make_error_code(ClientError::InvalidResponse));
        }
        
        std::string status_code_str = status_line.substr(first_space + 1, second_space - first_space - 1);
        std::string status_message = status_line.substr(second_space + 1);
        
        return std::make_pair(std::stoi(status_code_str), status_message);
    }

    void parse_headers(const std::string& headers, std::vector<std::pair<std::string, std::string>>& header_list) {
        size_t line_start = headers.find("\r\n") + 2; // Skip status line
        
        while (line_start < headers.length()) {
            size_t line_end = headers.find("\r\n", line_start);
            if (line_end == std::string::npos) break;
            
            std::string line = headers.substr(line_start, line_end - line_start);
            size_t colon_pos = line.find(':');
            
            if (colon_pos != std::string::npos) {
                std::string name = line.substr(0, colon_pos);
                std::string value = line.substr(colon_pos + 1);
                
                // Trim whitespace from value
                size_t value_start = value.find_first_not_of(' ');
                if (value_start != std::string::npos) {
                    value = value.substr(value_start);
                }
                
                header_list.emplace_back(std::move(name), std::move(value));
            }
            
            line_start = line_end + 2;
        }
    }
    
    std::expected<HttpResponse, std::error_code> parse_http_response(
        const std::string& response, 
        std::chrono::milliseconds latency
    ) {
        if (response.empty()) {
            return std::unexpected(make_error_code(ClientError::InvalidResponse));
        }
        
        HttpResponse http_response;
        http_response.latency = latency;
        
        // Find header/body separator
        size_t header_end = response.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            return std::unexpected(make_error_code(ClientError::InvalidResponse));
        }
        
        std::string headers = response.substr(0, header_end);
        http_response.body = response.substr(header_end + 4);
        
        // Extract and parse status line
        auto status_result = parse_status_line(headers);
        if (!status_result.has_value()) {
            return std::unexpected(status_result.error());
        }
        
        std::tie(http_response.status_code, http_response.status_message) = *status_result;
        
        // Parse remaining headers
        parse_headers(headers, http_response.headers);
        
        return http_response;
    }
    
    void cleanup() {
        ssl_.reset();
        ssl_ctx_.reset();
        
        if (socket_fd_ != -1) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
    }
};

void log_response(const HttpResponse& response) {
    std::println("\n=== HTTP Response Analysis ===");
    std::println("Status: {} {}", response.status_code, response.status_message);
    std::println("Request Latency: {}ms", response.latency.count());
    
    std::println("\n--- Response Headers ---");
    for (const auto& [name, value] : response.headers) {
        std::println("{}: {}", name, value);
    }
    
    std::println("\n--- Response Body ---");
    if (!response.body.empty()) {
        std::println("{}", response.body);
    } else {
        std::println("(empty)");
    }
    std::println("Body Size: {} bytes", response.body.size());
}

} // namespace fintech::tls_client

int main() {
    using namespace fintech::tls_client;
    
    try {
        std::println("=== Fintech TLS Client v1.0 ===");
        std::println("Connecting to api.bank.example.com:443 with TLS 1.3...");
        
        SecureTlsClient client;
        
        // Connect to server
        auto connect_result = client.connect("api.bank.example.com", 443);
        if (!connect_result.has_value()) {
            std::println(stderr, "Connection failed: {}", connect_result.error().message());
            return 1;
        }
        
        // Send GET request to balance endpoint
        auto response_result = client.send_get_request("/v1/balance");
        if (!response_result.has_value()) {
            std::println(stderr, "Request failed: {}", response_result.error().message());
            return 1;
        }
        
        // Log structured response
        log_response(*response_result);
        
        std::println("\n=== Request completed successfully ===");
        return 0;
        
    } catch (const std::exception& e) {
        std::println(stderr, "Unexpected error: {}", e.what());
        return 1;
    }
}
