# OpenVPN Plugin 使用示例

## 文件读取功能说明

本插件会自动读取证书和密钥文件的内容并存储在内存中，而不仅仅是保存文件路径。这样做的好处是：

1. **安全性**：文件内容加载后，即使源文件被删除或修改，也不会影响运行中的配置
2. **性能**：避免重复的文件 I/O 操作
3. **一致性**：确保所有证书和密钥在配置时就已验证可读

## 支持的文件类型

以下文件会被读取并存储完整内容：
- CA 证书 (`ca-cert`)
- 服务器证书 (`server-cert`)
- 服务器私钥 (`server-key`)
- DH 参数文件 (`dh-params`)
- TLS-Crypt 密钥 (`tls-crypt-key`)

## 使用示例

### 1. 准备证书文件

首先，确保你有以下文件（示例路径）：

```bash
/etc/openvpn/
├── ca.crt          # CA 证书
├── server.crt      # 服务器证书
├── server.key      # 服务器私钥
├── dh2048.pem      # DH 参数
└── ta.key          # TLS-Crypt 密钥（可选）
```

### 2. 启用 OpenVPN 并加载证书

#### 基本配置（TUN 模式，默认 MTU）

```bash
vpp# ovpn enable port 1194 \
  dev tun0 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key \
  dh-params /etc/openvpn/dh2048.pem \
  tls-crypt-key /etc/openvpn/ta.key \
  server-addr 10.8.0.1/24 \
  pool-start 10.8.0.10 \
  pool-end 10.8.0.250 \
  cipher AES-256-GCM \
  auth SHA256
```

#### TAP 模式配置（L2 桥接，自定义 MTU）

```bash
vpp# ovpn enable port 1194 \
  dev tap0 \
  mode tap \
  mtu 1500 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key \
  server-addr 10.8.0.1/24
```

#### 自定义 MTU 的 TUN 配置

```bash
vpp# ovpn enable port 1194 \
  dev tun0 \
  mode tun \
  mtu 1380 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key \
  server-addr 10.8.0.1/24
```

### 3. 查看加载结果

命令执行后会显示每个文件的加载状态和接口创建信息：

```
Loaded CA certificate from /etc/openvpn/ca.crt (1234 bytes)
Loaded server certificate from /etc/openvpn/server.crt (1456 bytes)
Loaded server key from /etc/openvpn/server.key (1704 bytes)
Loaded DH parameters from /etc/openvpn/dh2048.pem (424 bytes)
Loaded TLS-Crypt key from /etc/openvpn/ta.key (636 bytes)
Initialized picotls context
Created OpenVPN interface tun0 (sw_if_index 1, mode TUN, mtu 1420)
Set interface address: 10.8.0.1/24
Registered UDP port 1194 (IPv4/IPv6)
OpenVPN enabled on port 1194
```

### 4. 查看当前配置

```bash
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
  Max Clients: 100
  Keepalive Ping: 10 seconds
  Keepalive Timeout: 120 seconds
  Handshake Timeout: 60 seconds
  Renegotiate: 3600 seconds
  Replay Protection: Enabled
  Replay Window: 64
  Replay Time: 15 seconds
  Transition Window: 3600 seconds
```

## 错误处理

### 文件不存在

如果指定的文件不存在，会返回错误：

```bash
vpp# ovpn enable ca-cert /nonexistent/ca.crt
failed to read CA certificate: failed to read file '/nonexistent/ca.crt': stat `/nonexistent/ca.crt': No such file or directory
```

### 文件权限问题

如果 VPP 进程没有读取文件的权限：

```bash
vpp# ovpn enable ca-cert /root/private/ca.crt
failed to read CA certificate: failed to read file '/root/private/ca.crt': open `/root/private/ca.crt': Permission denied
```

**解决方法**：
```bash
# 确保 VPP 进程有读取权限
sudo chmod 644 /etc/openvpn/ca.crt
sudo chmod 644 /etc/openvpn/server.crt
sudo chmod 600 /etc/openvpn/server.key  # 私钥应该更严格
```

## 最小配置示例

最简单的配置（仅必需参数）：

```bash
vpp# ovpn enable port 1194 \
  server-addr 10.8.0.0/24 \
  pool-start 10.8.0.10 \
  pool-end 10.8.0.250
OpenVPN enabled on port 1194
```

## 完整配置示例

包含所有选项的完整配置：

```bash
vpp# ovpn enable \
  port 1194 \
  dev tun0 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key \
  dh-params /etc/openvpn/dh2048.pem \
  tls-crypt-key /etc/openvpn/ta.key \
  cipher AES-256-GCM \
  auth SHA256 \
  server-addr 10.8.0.0/24 \
  pool-start 10.8.0.10 \
  pool-end 10.8.0.250 \
  max-clients 200 \
  keepalive-ping 10 \
  keepalive-timeout 120 \
  handshake-timeout 60 \
  renegotiate-seconds 3600 \
  replay-protection 1 \
  replay-window 64 \
  replay-time 15 \
  transition-window 3600
```

## IPv6 配置示例

```bash
vpp# ovpn enable \
  port 1194 \
  server-addr fd00::/64 \
  pool-start fd00::10 \
  pool-end fd00::250 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key
```

## 禁用 OpenVPN

```bash
vpp# ovpn disable
OpenVPN disabled
```

## 技术细节

### 内存管理

- 文件内容使用 VPP 的 vector (`vec_t`) 存储
- 自动处理内存分配和释放
- 使用 `clib_file_contents()` 函数读取文件

### 文件读取函数

```c
static clib_error_t *
ovpn_read_file_contents (char *file_path, u8 **result)
{
  clib_error_t *error;
  
  if (!file_path)
    return clib_error_return (0, "file path is NULL");
    
  error = clib_file_contents (file_path, result);
  if (error)
    return clib_error_return (0, "failed to read file '%s': %U",
                              file_path, format_clib_error, error);
  
  return 0;
}
```

### 数据结构

证书和密钥在 `ovpn_options_t` 中的定义：

```c
typedef struct ovpn_options_t_ {
  // ... 其他字段 ...
  
  /* TLS - 存储文件内容，不是路径 */
  u8 *ca_cert;          // CA 证书内容
  u8 *server_cert;      // 服务器证书内容
  u8 *server_key;       // 服务器私钥内容
  u8 *dh_params;        // DH 参数内容
  u8 *tls_crypt_key;    // TLS-Crypt 密钥内容
  
  /* 算法名称 - 存储字符串 */
  u8 *cipher_name;      // 加密算法名称
  u8 *auth_name;        // 认证算法名称
  
  // ... 其他字段 ...
} ovpn_options_t;
```

## 生成测试证书

如果你需要生成测试证书：

```bash
# 安装 easy-rsa
sudo apt-get install easy-rsa

# 初始化 PKI
cd /usr/share/easy-rsa
./easyrsa init-pki

# 构建 CA
./easyrsa build-ca nopass

# 生成服务器证书和密钥
./easyrsa build-server-full server nopass

# 生成 DH 参数
./easyrsa gen-dh

# 生成 TLS-Crypt 密钥
openvpn --genkey --secret ta.key

# 证书位置
CA证书: pki/ca.crt
服务器证书: pki/issued/server.crt
服务器密钥: pki/private/server.key
DH参数: pki/dh.pem
```

## 安全建议

1. **私钥权限**：服务器私钥文件应该设置为 600 权限
   ```bash
   chmod 600 /etc/openvpn/server.key
   ```

2. **文件所有权**：确保 VPP 进程用户可以读取文件
   ```bash
   chown vpp:vpp /etc/openvpn/*
   ```

3. **证书验证**：在生产环境中使用前，验证证书有效性
   ```bash
   openssl verify -CAfile ca.crt server.crt
   ```

4. **密钥长度**：推荐使用至少 2048 位 RSA 密钥或 256 位 ECC 密钥

5. **定期更新**：定期更新证书，避免过期

## 故障排查

### 问题：无法读取文件

**检查文件是否存在**：
```bash
ls -la /etc/openvpn/ca.crt
```

**检查文件权限**：
```bash
sudo -u vpp cat /etc/openvpn/ca.crt
```

### 问题：证书格式错误

确保证书是 PEM 格式：
```bash
openssl x509 -in /etc/openvpn/ca.crt -text -noout
```

### 问题：内存不足

大文件可能导致内存问题，检查文件大小：
```bash
du -h /etc/openvpn/*
```

## 参考资料

- [OpenVPN 官方文档](https://openvpn.net/community-resources/)
- [VPP 文档](https://fd.io/docs/vpp/)
- [Easy-RSA 文档](https://easy-rsa.readthedocs.io/)

