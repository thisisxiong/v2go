![GitHub last commit](https://img.shields.io/github/last-commit/Danialsamadi/v2go.svg) [![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/) [![Update Configs](https://github.com/Danialsamadi/v2go/actions/workflows/update-configs.yml/badge.svg)](https://github.com/Danialsamadi/v2go/actions/workflows/update-configs.yml) ![GitHub repo size](https://img.shields.io/github/repo-size/Danialsamadi/v2go) ![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)

# High-Performance V2Ray Config Aggregator (Go Edition) 🚀

💻 A blazingly fast Go rewrite of [Epodonios/v2ray-configs](https://github.com/Epodonios/v2ray-configs) with **dramatic performance improvements** and enhanced features. This Go-based V2Ray configuration aggregator collects, processes, and organizes thousands of V2Ray configs with 99.7% better performance than the original Python implementation.

## 🔥 Performance Highlights

- **⚡ 99.7% Faster**: Reduced processing time from ~2 hours to ~14 seconds
- **🎯 Smart Deduplication**: Removes 95%+ duplicate configurations automatically  
- **🔄 Concurrent Processing**: 10 parallel workers for maximum efficiency
- **💾 Memory Optimized**: Streaming I/O with connection pooling
- **📊 Real-time Statistics**: Detailed processing metrics and protocol breakdown

### Performance Comparison
| Version | Runtime | Success Rate | Configs Processed |
|---------|---------|--------------|-------------------|
| Python  | ~2 hours | Frequent failures | ~450k |
| **Go**  | **~14 seconds** | **100% reliable** | **450k+** |

## 🛠️ Supported Protocols

- **VLESS** (Primary - ~335k configs)
- **Shadowsocks (SS)** (~69k configs)  
- **VMess** (~25k configs)
- **Trojan** (~17k configs)
- **ShadowsocksR (SSR)** (~86 configs)

## 🚀 Quick Start

### Prerequisites
- Go 1.21 or higher
- Git

### Installation & Usage

```bash
# Clone the repository
git clone https://github.com/Danialsamadi/v2go.git
cd v2go/Files

# Build the aggregator
go build -o aggregator main.go sort.go

# Run the aggregator
./aggregator

# Sort configs by protocol (optional)
go run sort.go
```

### Automated Updates
The repository includes GitHub Actions workflow that automatically updates configurations every 6 hours.

## 📁 Output Structure

```
v2go/
├── All_Configs_Sub.txt              # All configs (plain text)
├── All_Configs_base64_Sub.txt       # All configs (base64 encoded)
├── Splitted-By-Protocol/            # Protocol-specific files
│   ├── vless.txt
│   ├── vmess.txt  
│   ├── ss.txt
│   ├── ssr.txt
│   └── trojan.txt
└── Sub1.txt - Sub14.txt            # Split into 500-config chunks
```

## 🔗 Subscription Links

### All Configurations

**Main subscription (recommended):**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/All_Configs_Sub.txt
```

**Base64 encoded (if main link fails):**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/All_Configs_base64_Sub.txt
```

### Protocol-Specific Subscriptions

**VLESS:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vless.txt
```

**VMess:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/vmess.txt
```

**Shadowsocks:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/ss.txt
```

**ShadowsocksR:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/ssr.txt
```

**Trojan:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Protocol/trojan.txt
```

### Split Subscriptions (500 configs each)

<details>
<summary>Click to expand all split subscription links</summary>

**Config List 1:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub1.txt
```

**Config List 2:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub2.txt
```

**Config List 3:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub3.txt
```

**Config List 4:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub4.txt
```

**Config List 5:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub5.txt
```

**Config List 6:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub6.txt
```

**Config List 7:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub7.txt
```

**Config List 8:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub8.txt
```

**Config List 9:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub9.txt
```

**Config List 10:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub10.txt
```

**Config List 11:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub11.txt
```

**Config List 12:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub12.txt
```

**Config List 13:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub13.txt
```

**Config List 14:**
```
https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub14.txt
```

</details>

## 📱 Compatible V2Ray Clients

### Android
- **v2rayNG** (Recommended)
- **Clash for Android**

### iOS  
- **Fair VPN**
- **Streisand**
- **Shadowrocket**

### Windows & Linux
- **Hiddify Next** (Recommended)
- **Nekoray**
- **v2rayN**
- **Clash Verge**

### macOS
- **V2rayU**
- **ClashX**

## 📖 Usage Instructions

### Mobile & Desktop Clients

1. **Copy** one of the subscription links above
2. **Open** your V2Ray client's subscription settings
3. **Paste** the link and save the subscription
4. **Update** subscriptions regularly to get fresh configs
5. **Test** different configs to find the best performance for your location

### System-Wide Proxy Setup

#### Method 1: Using Proxifier (Recommended)

1. **Download** and install [Proxifier](https://proxifier.com/download/)

2. **Activate** with one of these keys:
   - Portable: `L6Z8A-XY2J4-BTZ3P-ZZ7DF-A2Q9C`
   - Standard: `5EZ8G-C3WL5-B56YG-SCXM9-6QZAP`  
   - macOS: `P427L-9Y552-5433E-8DSR3-58Z68`

3. **Configure** proxy server:
   - IP: `127.0.0.1`
   - Port: `10808` (v2rayN) / `2801` (Netch) / `1080` (SSR) / `1086` (V2rayU)
   - Protocol: `SOCKS5`

#### Method 2: System Proxy Settings

1. **Open** your OS network/proxy settings
2. **Configure** SOCKS5 proxy:
   - IP: `127.0.0.1`
   - Port: `10809`
   - Bypass: `localhost;127.*;10.*;172.16.*-172.31.*;192.168.*`
3. **Enable** system proxy in your V2Ray client

## 🏗️ Architecture & Features

### Core Components

- **`main.go`**: High-performance config aggregator with concurrent processing
- **`sort.go`**: Protocol-based config sorter with deduplication
- **GitHub Actions**: Automated config updates every 6 hours

### Key Optimizations

- **Concurrent HTTP Requests**: 10 parallel workers vs sequential processing
- **Connection Pooling**: Reuses HTTP connections for better performance  
- **Streaming I/O**: Memory-efficient file operations
- **Smart Deduplication**: Hash-based duplicate detection (95%+ reduction)
- **Native Base64**: Go's optimized encoding vs Python libraries

### Statistics Example
```
Configuration aggregation completed!
Total time: 13.854 seconds
Configurations processed: 451,408
After deduplication: 21,980 unique configs
Duplicates removed: 429,428 (95.1% reduction)

Protocol breakdown:
- vless: 335,247 configs
- ss: 69,158 configs  
- vmess: 25,891 configs
- trojan: 17,112 configs
- ssr: 86 configs
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔍 VPN Configuration Scanner

The project now includes a powerful **VPN Configuration Scanner** in the `scanner/` directory:

### Features
- **Multi-Protocol Support**: VMess, VLess, Trojan, Shadowsocks
- **Lightning Fast**: Processes 15,795+ configs in ~100ms
- **Smart Filtering**: Optional latency measurement and speed categorization
- **Comprehensive Testing**: 84.1% test coverage with benchmarks

### Quick Start
```bash
# Navigate to scanner directory
cd scanner/

# Fast scanning (no latency measurement)
go run scanner_main.go scanner.go -dir=.. -timeout=1s

# With latency measurement (slower but more accurate)
go run scanner_main.go scanner.go -dir=.. -timeout=1s -latency

# Run tests
go test -v
```

See `scanner/README.md` for complete documentation.

## ⭐ Acknowledgments

- **Original Repository**: This project is a Go rewrite of [Epodonios/v2ray-configs](https://github.com/Epodonios/v2ray-configs) - all credit for the original concept and Python implementation goes to the original authors
- **V2Ray Community**: For protocol specifications and documentation
- **Go Community**: For the excellent performance and concurrency features that made this optimization possible
- **Contributors and Testers**: For feedback and improvements

---
## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Danialsamadi/v2go&type=Date)](https://www.star-history.com/#Danialsamadi/v2go&Date&LogScale)

---
**Made with ❤️ by Dani Samadi**

*If you find this project useful, please consider giving it a ⭐ star!*
