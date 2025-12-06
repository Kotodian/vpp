# OpenVPN CLI 命令使用说明

## 概述

本插件提供了两个主要的 CLI 命令来配置和管理 OpenVPN 服务器。

## 命令列表

### 1. `ovpn` - 启用/禁用 OpenVPN 服务器

#### 语法

```
ovpn [enable|disable] [选项...]
```

#### 选项

**基本选项：**
- `enable` - 启用 OpenVPN 服务器
- `disable` - 禁用 OpenVPN 服务器
- `port <port>` - 监听端口（默认: 1194）
- `dev <name>` - 设备/接口名称（例如: tun0, tap0）
- `mode tun|tap` - 接口模式（tun=L3 IP隧道，tap=L2以太网桥接，默认: tun）
- `mtu <size>` - 接口 MTU 大小（默认: 1420）

**TLS/SSL 证书选项：**
- `ca-cert <path>` - CA 证书路径
- `server-cert <path>` - 服务器证书路径
- `server-key <path>` - 服务器私钥路径
- `dh-params <path>` - Diffie-Hellman 参数文件路径
- `cipher <name>` - 加密算法名称
- `auth <name>` - 认证算法名称
- `tls-crypt-key <path>` - TLS-Crypt 密钥路径

**网络配置选项：**
- `server-addr <ip>/<len>` - 服务器地址和子网掩码（支持 IPv4/IPv6）
- `pool-start <ip>` - 客户端 IP 池起始地址
- `pool-end <ip>` - 客户端 IP 池结束地址
- `max-clients <n>` - 最大客户端数量（默认: 100）

**超时和定时器选项：**
- `keepalive-ping <sec>` - Keepalive ping 间隔（默认: 10 秒）
- `keepalive-timeout <sec>` - Keepalive 超时时间（默认: 120 秒）
- `handshake-timeout <sec>` - 握手超时时间（默认: 60 秒）
- `renegotiate-seconds <sec>` - 重新协商间隔（默认: 3600 秒）
- `transition-window <sec>` - 过渡窗口时间（默认: 3600 秒）

**重放保护选项：**
- `replay-protection <0|1>` - 启用/禁用重放保护（默认: 1）
- `replay-window <n>` - 重放窗口大小（默认: 64）
- `replay-time <sec>` - 重放时间窗口（默认: 15 秒）

#### 使用示例

**示例 1：基本启用（TUN 模式，默认 MTU）**
```
ovpn enable port 1194 dev tun0 server-addr 10.8.0.1/24 pool-start 10.8.0.10 pool-end 10.8.0.250
```

**示例 2：TAP 模式配置（L2 桥接）**
```
ovpn enable port 1194 dev tap0 mode tap mtu 1500 server-addr 10.8.0.1/24
```

**示例 3：自定义 MTU 的 TUN 配置**
```
ovpn enable port 1194 dev tun0 mode tun mtu 1380 server-addr 10.8.0.1/24
```

**示例 4：带 TLS 证书配置**
```
ovpn enable port 1194 dev tun0 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key \
  dh-params /etc/openvpn/dh2048.pem \
  cipher AES-256-GCM \
  auth SHA256 \
  server-addr 10.8.0.1/24
```

**示例 5：使用 IPv6**
```
ovpn enable port 1194 dev tun0 server-addr fd00::1/64 pool-start fd00::10 pool-end fd00::250
```

**示例 6：自定义超时设置**
```
ovpn enable port 1194 dev tun0 \
  server-addr 10.8.0.1/24 \
  keepalive-ping 15 \
  keepalive-timeout 180 \
  handshake-timeout 90 \
  renegotiate-seconds 7200
```

**示例 7：完整配置示例**
```
ovpn enable port 1194 \
  dev tun0 \
  mode tun \
  mtu 1420 \
  server-addr 10.8.0.1/24 \
  pool-start 10.8.0.10 \
  pool-end 10.8.0.250 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key \
  cipher AES-256-GCM \
  auth SHA256 \
  max-clients 200 \
  keepalive-ping 10 \
  keepalive-timeout 120 \
  replay-protection 1 \
  replay-window 64
```

**示例 8：禁用 OpenVPN**
```
ovpn disable
```

### 2. `show ovpn` - 显示 OpenVPN 配置

#### 语法

```
show ovpn
```

#### 说明

显示当前 OpenVPN 服务器的所有配置选项，包括：
- 启用状态
- 监听端口和协议
- Picotls 上下文初始化状态
- 设备名称、模式（TUN/TAP）和 MTU
- 软件接口索引
- 服务器地址
- TLS/SSL 证书加载状态（显示字节数）
- 加密和认证设置
- 客户端 IP 池配置
- 各种超时和定时器设置
- 重放保护设置

#### 使用示例

```
vpp# show ovpn
OpenVPN Configuration:
  Status: Enabled
  Listen Port: 1194
  Protocol: UDP
  Picotls Context: Initialized
  Device Name: tun0
  Device Mode: TUN (L3)
  MTU: 1420
  SW Interface Index: 1
  Server Address: 10.8.0.1/24
  CA Certificate: loaded (1234 bytes)
  Server Certificate: loaded (1456 bytes)
  Server Key: loaded (1704 bytes)
  DH Parameters: loaded (424 bytes)
  TLS-Crypt Key: loaded (636 bytes)
  Cipher: AES-256-GCM
  Auth: SHA256
  Pool Start: 10.8.0.10
  Pool End: 10.8.0.250
  Max Clients: 200
  Keepalive Ping: 10 seconds
  Keepalive Timeout: 120 seconds
  Handshake Timeout: 60 seconds
  Renegotiate: 3600 seconds
  Replay Protection: Enabled
  Replay Window: 64
  Replay Time: 15 seconds
  Transition Window: 3600 seconds
```

## 接口模式说明

### TUN 模式（默认）

**用途**: Layer 3 IP 隧道

**特点**:
- 工作在 IP 层，传输 IP 数据包
- 适合点对点 VPN 连接
- 推荐 MTU: 1420（为 OpenVPN 头部预留空间）
- 更高效的封装，较小的开销

**示例**:
```
ovpn enable dev tun0 mode tun mtu 1420 port 1194 server-addr 10.8.0.1/24
```

### TAP 模式

**用途**: Layer 2 以太网桥接

**特点**:
- 工作在以太网层，传输以太网帧
- 适合需要桥接网络的场景
- 支持非 IP 协议（如 IPX、AppleTalk）
- 推荐 MTU: 1500（标准以太网 MTU）
- 可以在 VPN 上运行 DHCP 服务器

**示例**:
```
ovpn enable dev tap0 mode tap mtu 1500 port 1194 server-addr 10.8.0.1/24
```

### MTU 选择建议

| 模式 | 推荐 MTU | 说明 |
|------|----------|------|
| TUN | 1420 | 避免 IP 分片，OpenVPN 头部约占 80 字节 |
| TAP | 1500 | 标准以太网 MTU |
| 受限网络 | 1380-1400 | 如果存在额外的隧道封装（如 PPPoE） |

## 注意事项

1. 启用或禁用 OpenVPN 时，必须明确指定 `enable` 或 `disable` 参数。
2. 所有路径参数（证书、密钥等）应使用绝对路径。
3. 证书和密钥文件会被读取并存储在内存中（显示为字节数）。
4. IP 地址支持 IPv4 和 IPv6 格式。
5. 端口范围：1-65535（建议使用标准 OpenVPN 端口 1194）。
6. 最大客户端数量取决于系统资源和网络配置。
7. 接口名称支持自定义（如 tun0, tap0, vpn0 等）。
8. MTU 应根据网络环境和接口模式合理设置。

## 开发状态

当前实现包含：
- ✅ CLI 命令解析和参数验证
- ✅ 配置选项存储
- ✅ 配置信息显示

待实现功能：
- ⏳ 实际的 OpenVPN 服务器初始化逻辑
- ⏳ 动态配置更新
- ⏳ 连接状态监控
- ⏳ 客户端管理命令

## 技术细节

### 数据结构

配置选项存储在 `ovpn_options_t` 结构中，定义在 `ovpn_options.h`：

```c
typedef struct ovpn_options_t_ {
  u16 listen_port;
  u32 proto;
  char *dev_name;
  fib_prefix_t server_addr;
  u8 *ca_cert;
  u8 *server_cert;
  u8 *server_key;
  u8 *dh_params;
  u8 *cipher_name;
  u8 *auth_name;
  u8 replay_protection;
  u32 replay_window;
  u32 replay_time;
  u32 renegotiate_seconds;
  u32 handshake_timeout;
  u32 transition_window;
  ip_address_t pool_start;
  ip_address_t pool_end;
  u32 max_clients;
  u32 keepalive_ping;
  u32 keepalive_timeout;
  u8 *tls_crypt_key;
} ovpn_options_t;
```

### 全局状态

OpenVPN 主状态存储在全局变量 `ovpn_main`：

```c
extern ovpn_main_t ovpn_main;
```

## 参考资料

- VPP CLI 开发文档：https://fd.io/docs/vpp/
- OpenVPN 协议规范
- VPP 插件开发指南

