// main.cpp
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/blake2.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
using tcp = net::ip::tcp;

/* ======================= UTILITIES ======================= */

std::string to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; i++)
        ss << std::uppercase << std::hex << std::setw(2)
           << std::setfill('0') << (int)data[i];
    return ss.str();
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

/* ======================= HWID HASH ======================= */

std::string format_hwid(const std::string& data) {
    unsigned char sha3[64], sha256_[32], sha512_[64], blake[28];

    // SHA3-512
    EVP_Digest(data.data(), data.size(), sha3, nullptr, EVP_sha3_512(), nullptr);

    // SHA256
    SHA256(sha3, 64, sha256_);

    // SHA512
    SHA512(sha256_, 32, sha512_);

    // BLAKE2b (28 bytes)
    BLAKE2B_CTX ctx;
    BLAKE2b_Init(&ctx, 28);
    BLAKE2b_Update(&ctx, sha512_, 64);
    BLAKE2b_Final(blake, &ctx);

    return to_hex(blake, 28);
}

/* ======================= HWID COLLECTOR (Linux/Android) ======================= */

std::string get_hwid() {
    std::string raw;

    raw += read_file("/etc/machine-id");
    raw += read_file("/var/lib/dbus/machine-id");
    raw += read_file("/proc/cpuinfo");

    if (raw.empty())
        raw = std::to_string(getuid());

    return format_hwid(raw);
}

/* ======================= HTTPS GET USING BOOST ======================= */

std::string https_get(const std::string& host, const std::string& target) {
    net::io_context ioc;
    net::ssl::context ctx(net::ssl::context::sslv23_client);
    ctx.set_default_verify_paths();

    tcp::resolver resolver(ioc);
    beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

    auto const results = resolver.resolve(host, "443");
    beast::get_lowest_layer(stream).connect(results);
    stream.handshake(net::ssl::stream_base::client);

    http::request<http::string_body> req{http::verb::get, target, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::cache_control, "no-store, no-cache, must-revalidate, max-age=0");
    req.set(http::field::pragma, "no-cache");

    http::write(stream, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(stream, buffer, res);

    beast::error_code ec;
    stream.shutdown(ec);

    return res.body();
}

/* ======================= MAIN ======================= */

int main() {
    try {
        std::string hwid = get_hwid();
        std::string host = "zromalu.vercel.app";
        std::string target = "/api?key=" + hwid;

        std::string response = https_get(host, target);
        json j = json::parse(response);

        std::string status = j.value("status", "");

        if (status == "NONE") {
            std::cout << "YOU ARE NOT A PREMIUM USER\nKEY: " << hwid << "\n";
            return 0;
        }
        else if (status == "ACTIVE") {
            std::cout << "Welcome " << j.value("user", "User") << "!\n";
        }
        else if (status == "BLOCKED") {
            std::cout << "YOU ARE A BLOCKED USER\n";
            return 0;
        }
        else if (status == "MAINTENANCE") {
            std::cout << "TOOL IS UNDER MAINTENANCE\n";
            return 0;
        }
        else if (status == "EXPIRED") {
            std::cout << "YOUR SUBSCRIPTION WAS EXPIRED\nKEY: " << hwid << "\n";
            return 0;
        }
        else {
            std::cout << "Something went wrong\n";
            return 0;
        }
    }
    catch (std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
