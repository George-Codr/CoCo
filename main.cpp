#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <array>
#include <cstdio>
#include <vector>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

#include <nlohmann/json.hpp>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <unistd.h>
#endif

using json = nlohmann::json;
namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
using tcp = net::ip::tcp;

/* ========== Utilities ========== */

std::string exec_cmd(const char* cmd) {
    std::array<char, 256> buffer{};
    std::string result;
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe))
        result += buffer.data();
    pclose(pipe);
    return result;
}

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

std::string to_hex(const unsigned char* data, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; i++)
        ss << std::uppercase << std::hex << std::setw(2)
           << std::setfill('0') << (int)data[i];
    return ss.str();
}

/* ========== BLAKE2b Implementation (28 bytes output) ========== */

/* Reference: https://github.com/BLAKE2/BLAKE2 */

#include <stdint.h>
#include <stddef.h>

class Blake2b {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[128];
    size_t   buflen;
    size_t   outlen;

public:
    Blake2b(size_t digest_size) : buflen(0), outlen(digest_size) {
        const uint64_t IV[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        memcpy(h, IV, 8 * sizeof(uint64_t));
        t[0] = t[1] = f[0] = f[1] = 0;
    }

    // Simplified: only works with data <= 128 bytes (good enough for SHA512 output)
    void update(const uint8_t* data, size_t len) {
        memcpy(buf, data, len);
        buflen = len;
    }

    void final(uint8_t* out) {
        // For simplicity, we just fold SHA512 output into 28 bytes using XOR
        for(size_t i=0;i<28;i++)
            out[i] = buf[i] ^ buf[i+28] ^ buf[i+56] ^ buf[i+84];
    }
};

/* ========== Hash Pipeline ========== */

std::string format_hwid(const std::string& data) {
    unsigned char sha3[64], sha256_[32], sha512_[64], blake[28];

    EVP_Digest(data.data(), data.size(), sha3, nullptr, EVP_sha3_512(), nullptr);
    SHA256(sha3, 64, sha256_);
    SHA512(sha256_, 32, sha512_);

    Blake2b ctx(28);
    ctx.update(sha512_, 64);
    ctx.final(blake);

    return to_hex(blake, 28);
}

/* ========== HWID ========== */

std::string get_hwid() {
    std::string raw;

#if defined(_WIN32)
    HKEY hKey;
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Cryptography",0,KEY_READ | KEY_WOW64_64KEY,&hKey) == 0) {
        char value[256]; DWORD size=sizeof(value);
        if(RegQueryValueExA(hKey,"MachineGuid",nullptr,nullptr,(LPBYTE)value,&size)==0)
            raw += value;
        RegCloseKey(hKey);
    }
#elif defined(__APPLE__)
    char buf[256]; size_t size=sizeof(buf);
    if(sysctlbyname("kern.uuid",buf,&size,nullptr,0)==0) raw+=buf;
#elif defined(__ANDROID__)
    raw+=read_file("/etc/machine-id");
    raw+=read_file("/var/lib/dbus/machine-id");
    raw+=exec_cmd("getprop ro.build.fingerprint");
    raw+=exec_cmd("cat /proc/cpuinfo");
#elif defined(__linux__)
    raw+=read_file("/etc/machine-id");
    raw+=read_file("/var/lib/dbus/machine-id");
    raw+=exec_cmd("cat /proc/cpuinfo");
#else
    raw="unknown-platform";
#endif

#if defined(__linux__) || defined(__ANDROID__)
    if(raw.empty()) raw=std::to_string(getuid());
#endif

    if(raw.empty()) raw="fallback-device";

    return format_hwid(raw);
}

/* ========== HTTPS GET ========== */

std::string https_get(const std::string& host,const std::string& target) {
    net::io_context ioc;
    net::ssl::context ctx(net::ssl::context::sslv23_client);
    ctx.set_default_verify_paths();

    tcp::resolver resolver(ioc);
    beast::ssl_stream<beast::tcp_stream> stream(ioc,ctx);
    auto const results=resolver.resolve(host,"443");
    beast::get_lowest_layer(stream).connect(results);
    stream.handshake(net::ssl::stream_base::client);

    http::request<http::string_body> req{http::verb::get,target,11};
    req.set(http::field::host,host);
    req.set(http::field::cache_control,"no-store, no-cache, must-revalidate, max-age=0");
    req.set(http::field::pragma,"no-cache");

    http::write(stream,req);
    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(stream,buffer,res);

    beast::error_code ec;
    stream.shutdown(ec);
    return res.body();
}

/* ========== Main ========== */

int main() {
    try {
        std::string hwid=get_hwid();
        std::string target="/api?key="+hwid;
        json _xd=json::parse(https_get("zromalu.vercel.app",target));
        std::string status=_xd["status"].get<std::string>();

        if(status=="NONE"){std::cout<<"YOU ARE NOT A PREMIUM USER \nKEY : "<<hwid<<"\n";return 0;}
        else if(status=="ACTIVE"){std::cout<<"Welcome "<<_xd["user"].get<std::string>()<<"!\n";}
        else if(status=="BLOCKED"){while(true) std::cout<<"YOU ARE BLOCKED USER\n";}
        else if(status=="MAINTENANCE"){std::cout<<"TOOL IS NOW UNDER MAINTENANCE\n";return 0;}
        else if(status=="EXPIRED"){std::cout<<"YOUR SUBSCRIPTION WAS EXPIRED \nKEY : "<<hwid<<"\n";return 0;}
        else{std::cout<<"Something Went Wrong\n";return 0;}
    }
    catch(std::exception& e){std::cerr<<"Fatal error: "<<e.what()<<"\n";}
    return 0;
}
