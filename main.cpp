#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <array>
#include <cstdio>
#include <blake3.h>
#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#elif defined(__linux__) || defined(__ANDROID__)
#include <unistd.h>
#endif
using namespace std;
using json = nlohmann::json;

string read_file(const string& path) {
    ifstream f(path, ios::binary);
    if (!f) return "";
    return string((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
}

string exec_cmd(const string& cmd) {
    array<char,512> buf{};
    string res;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buf.data(), buf.size(), pipe)) res += buf.data();
    pclose(pipe);
    return res;
}

#if defined(_WIN32)
string get_wmi_value(const string& cls, const string& prop) {
    string cmd = "powershell -NoP -Exec Bypass -C \"Get-WmiObject -Class " + cls + " | Select-Object -First 1 -ExpandProperty " + prop + "\"";
    string out = exec_cmd(cmd);
    while (!out.empty() && isspace(static_cast<unsigned char>(out.back()))) out.pop_back();
    return out;
}
#endif

string get_hwid() {
    string raw;
#if defined(_WIN32)
    HKEY hKey{};
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        char buf[256]{};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS) raw += buf;
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char buf[256]{};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExA(hKey, "ProductId", nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS) raw += buf;
        RegCloseKey(hKey);
    }
    raw += get_wmi_value("Win32_ComputerSystemProduct", "UUID");
    raw += get_wmi_value("Win32_BaseBoard", "SerialNumber");
    raw += get_wmi_value("Win32_BIOS", "SerialNumber");
    for (char d : {'C','D','E'}) {
        string letter = string(1,d) + ":\\";
        DWORD ser = 0;
        if (GetVolumeInformationA(letter.c_str(), nullptr, 0, &ser, nullptr, nullptr, nullptr, 0)) raw += to_string(ser);
    }
#elif defined(__APPLE__)
    io_registry_entry_t root = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
    if (root) {
        CFStringRef uuid = (CFStringRef)IORegistryEntryCreateCFProperty(root, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
        if (uuid) {
            char buf[128]{};
            CFStringGetCString(uuid, buf, sizeof(buf), kCFStringEncodingUTF8);
            raw += buf;
            CFRelease(uuid);
        }
        IOObjectRelease(root);
    }
#elif defined(__ANDROID__)
    raw += exec_cmd("getprop ro.boot.serialno");
    raw += exec_cmd("getprop ro.build.fingerprint");
    raw += exec_cmd("getprop ro.product.vendor.name");
    raw += exec_cmd("getprop ro.product.vendor.device");
    raw += read_file("/persist/.ro.serialno");
#elif defined(__linux__)
    raw += read_file("/etc/machine-id");
    raw += read_file("/var/lib/dbus/machine-id");
    raw += exec_cmd("cat /sys/class/dmi/id/product_uuid 2>/dev/null");
    raw += exec_cmd("cat /sys/class/dmi/id/board_serial 2>/dev/null");
    raw += exec_cmd("cat /sys/class/dmi/id/product_serial 2>/dev/null");
    raw += exec_cmd("dmidecode --string system-uuid 2>/dev/null");
#endif
    if (raw.size() < 32) {
#if defined(__linux__) || defined(__ANDROID__)
        char host[256]{};
        gethostname(host, sizeof(host));
        raw += host;
        raw += to_string(getuid());
#endif
        raw += to_string(static_cast<uint64_t>(time(nullptr)));
    }
    return raw;
}

string to_hex(const unsigned char* data, size_t len) {
    stringstream ss;
    for (size_t i = 0; i < len; ++i)
        ss << uppercase << hex << setw(2) << setfill('0') << (int)data[i];
    return ss.str();
}

string format_hwid(const string& data) {
    if (data.empty()) return "00000000000000000000000000000000000000000000000000000000";
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data.data(), data.size());
    uint8_t digest[28]{};
    blake3_hasher_finalize(&hasher, digest, 28);
    return to_hex(digest, 28);
}

string https_get(const string& host, const string& target);

int main() {
    try {
        string hwid = format_hwid(get_hwid());
        string target = "/api?key=" + hwid;
        string response = https_get("zromalu.vercel.app", target);
        json j = json::parse(response);
        string status = j["status"].get<string>();
        if (status == "NONE") {
            cout << "YOU ARE NOT A PREMIUM USER \nKEY : " << hwid << "\n";
        } else if (status == "ACTIVE") {
            cout << "Welcome " << j["user"].get<string>() << "!\n";
        } else if (status == "BLOCKED") {
            while (true) cout << "YOU ARE BLOCKED USER\n";
        } else if (status == "MAINTENANCE") {
            cout << "TOOL IS NOW UNDER MAINTENANCE\n";
        } else if (status == "EXPIRED") {
            cout << "YOUR SUBSCRIPTION WAS EXPIRED \nKEY : " << hwid << "\n";
        } else {
            cout << "Something Went Wrong\n";
        }
    } catch (exception& e) {
        cerr << "Fatal error: " << e.what() << "\n";
    }
    return 0;
}
