# OpenVPN Picotls 集成文档

## 概述

本文档描述了 OpenVPN 插件中 Picotls 上下文的初始化和 UDP 端口注册的实现。

## 主要组件

### 1. Picotls 上下文 (ptls_context_t)

Picotls 是一个轻量级的 TLS 1.3 实现，用于 OpenVPN 的加密通信。

#### 数据结构

```c
typedef struct ovpn_main_t_ {
  ovpn_options_t options;
  
  /* Picotls context */
  ptls_context_t *ptls_ctx;
  
  /* UDP registration */
  u32 udp_node_index;
  u8 is_enabled;
  
  /* For convenience */
  vlib_main_t *vm;
  vnet_main_t *vnm;
} ovpn_main_t;
```

### 2. 密钥交换算法

支持的密钥交换算法（根据 OpenSSL 编译配置）：

```c
static ptls_key_exchange_algorithm_t *ovpn_key_exchange[] = {
  &ptls_openssl_x25519,      // Curve25519 (推荐)
  &ptls_openssl_secp256r1,   // NIST P-256
  &ptls_openssl_secp384r1,   // NIST P-384
  &ptls_openssl_secp521R1,   // NIST P-521
  NULL
};
```

### 3. 加密套件

支持的加密套件：

```c
static ptls_cipher_suite_t *ovpn_cipher_suites[] = {
  &ptls_openssl_aes128gcmsha256,         // AES-128-GCM with SHA-256
  &ptls_openssl_aes256gcmsha384,         // AES-256-GCM with SHA-384
  &ptls_openssl_chacha20poly1305sha256,  // ChaCha20-Poly1305 with SHA-256
  NULL
};
```

## 核心函数

### 1. 文件读取

```c
static clib_error_t *
ovpn_read_file_contents (char *file_path, u8 **result);
```

**功能**：读取文件内容到内存
- 使用 `clib_file_contents()` 读取文件
- 自动处理错误
- 返回 VPP vector 格式的数据

### 2. 证书加载

```c
static int
ovpn_load_certificates (ptls_context_t *ctx, u8 *cert_data, u8 *key_data);
```

**功能**：加载服务器证书和私钥到 Picotls 上下文

**步骤**：
1. 使用 OpenSSL BIO 从内存读取私钥（PEM 格式）
2. 使用 `PEM_read_bio_PrivateKey()` 解析私钥
3. 初始化签名证书结构 `ptls_openssl_sign_certificate_t`
4. 设置证书列表（原始 PEM 数据）

**示例**：
```c
if (omp->options.server_cert && omp->options.server_key) {
  if (ovpn_load_certificates(ctx, 
                             omp->options.server_cert,
                             omp->options.server_key) != 0) {
    // 处理错误
  }
}
```

### 3. Picotls 上下文初始化

```c
static clib_error_t *
ovpn_init_picotls_context (ovpn_main_t *omp);
```

**功能**：初始化 Picotls 上下文

**配置项**：
- `random_bytes`: 使用 OpenSSL 随机数生成器
- `key_exchanges`: 配置支持的密钥交换算法
- `cipher_suites`: 配置支持的加密套件
- `get_time`: 时间获取函数
- `require_dhe_on_psk`: 要求 PSK 使用 DHE
- `max_early_data_size`: 禁用 0-RTT（设为 0）

**使用**：
```c
error = ovpn_init_picotls_context(omp);
if (error) {
  // 处理错误
}
```

### 4. Picotls 上下文清理

```c
static void
ovpn_cleanup_picotls_context (ovpn_main_t *omp);
```

**功能**：清理和释放 Picotls 上下文资源

**清理项**：
- 释放证书列表
- 释放上下文结构
- 重置指针为 NULL

### 5. UDP 端口注册

当前实现为占位符，未来将实现：

```c
// IPv4 注册
udp_register_dst_port (vm, (u16) port, ovpn_node.index, 1);

// IPv6 注册
udp_register_dst_port (vm, (u16) port, ovpn_node.index, 0);
```

## CLI 命令流程

### 启用 OpenVPN

```bash
vpp# ovpn enable port 1194 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key
```

**执行流程**：

1. **解析参数** - 解析所有 CLI 参数
2. **读取证书文件** - 使用 `ovpn_read_file_contents()` 读取所有文件
3. **初始化 Picotls** - 调用 `ovpn_init_picotls_context()`
   - 分配上下文
   - 配置算法和套件
   - 加载证书和密钥
4. **注册 UDP 端口** - 标记为启用（实际注册待实现）
5. **输出状态** - 显示成功消息

**输出示例**：
```
Loaded CA certificate from /etc/openvpn/ca.crt (1234 bytes)
Loaded server certificate from /etc/openvpn/server.crt (1456 bytes)
Loaded server key from /etc/openvpn/server.key (1704 bytes)
Initialized picotls context
Registered UDP port 1194 (IPv4/IPv6)
OpenVPN enabled on port 1194
```

### 禁用 OpenVPN

```bash
vpp# ovpn disable
```

**执行流程**：

1. **清理 Picotls** - 调用 `ovpn_cleanup_picotls_context()`
2. **注销 UDP 端口** - 取消注册（待实现）
3. **清空配置** - 重置所有选项
4. **输出状态** - 显示禁用消息

### 查看状态

```bash
vpp# show ovpn
```

**输出示例**：
```
OpenVPN Configuration:
  Status: Enabled
  Listen Port: 1194
  Protocol: UDP
  Picotls Context: Initialized
  CA Certificate: loaded (1234 bytes)
  Server Certificate: loaded (1456 bytes)
  Server Key: loaded (1704 bytes)
  ...
```

## 安全考虑

### 1. 私钥安全

- 私钥从文件读取后存储在内存中
- 使用 `clib_mem_alloc()` 分配内存
- 私钥在 `ptls_openssl_sign_certificate_t` 中管理
- 禁用时应清理内存（建议添加安全清零）

### 2. 证书验证

当前实现：
- ✅ 加载服务器证书和私钥
- ⏳ CA 证书验证（待实现）
- ⏳ 客户端证书验证（待实现）
- ⏳ 证书链验证（待实现）

### 3. TLS 配置

- ✅ 使用 TLS 1.3
- ✅ 支持现代加密套件
- ✅ 禁用 0-RTT（防止重放攻击）
- ✅ 要求 DHE（完美前向保密）

## 错误处理

### 常见错误

1. **文件读取失败**
   ```
   failed to read CA certificate: failed to read file '/path/to/ca.crt': 
   No such file or directory
   ```

2. **证书格式错误**
   ```
   failed to load certificates
   ```
   - 检查证书是否为 PEM 格式
   - 验证私钥是否匹配证书

3. **内存分配失败**
   ```
   failed to allocate picotls context
   ```

## 性能考虑

### 内存使用

- Picotls 上下文：~200 字节
- 证书数据：取决于证书大小（通常 1-5 KB）
- 私钥数据：取决于密钥大小（通常 1-3 KB）

### CPU 使用

- 初始化：一次性操作，开销可忽略
- TLS 握手：使用硬件加速（如果可用）
- 数据加密：使用 AES-NI 等硬件指令

## 待实现功能

### 高优先级

1. **UDP 节点实现**
   - [ ] 创建 OpenVPN 输入节点
   - [ ] 实际注册 UDP 端口到节点
   - [ ] 实现数据包接收和分发

2. **CA 证书验证**
   - [ ] 加载 CA 证书链
   - [ ] 配置客户端证书验证

3. **会话管理**
   - [ ] TLS 会话创建和管理
   - [ ] 握手处理
   - [ ] 会话清理

### 中优先级

4. **DH 参数支持**
   - [ ] 加载 DH 参数
   - [ ] 配置到 Picotls

5. **TLS-Crypt 支持**
   - [ ] 加载 TLS-Crypt 密钥
   - [ ] 实现数据包加密/解密

6. **性能优化**
   - [ ] 零拷贝数据传输
   - [ ] 批处理数据包处理
   - [ ] 使用 VPP crypto 引擎

### 低优先级

7. **统计和监控**
   - [ ] TLS 握手成功/失败计数
   - [ ] 加密/解密性能统计
   - [ ] 连接状态监控

8. **高级功能**
   - [ ] 会话恢复
   - [ ] ALPN 支持
   - [ ] 自定义加密套件顺序

## 编译依赖

### 必需库

- **picotls**: TLS 1.3 实现
  ```bash
  apt-get install libpicotls-dev
  ```

- **OpenSSL**: 加密后端
  ```bash
  apt-get install libssl-dev
  ```

### CMakeLists.txt 配置

```cmake
vpp_find_path(PICOTLS_INCLUDE_DIR NAMES picotls.h)
vpp_find_library(PICOTLS_CORE_LIBRARY NAMES "libpicotls-core.a")
vpp_find_library(PICOTLS_OPENSSL_LIBRARY NAMES "libpicotls-openssl.a")

list (APPEND PICOTLS_LINK_LIBRARIES
    ${PICOTLS_CORE_LIBRARY}
    ${PICOTLS_OPENSSL_LIBRARY}
)

add_vpp_plugin(ovpn
  SOURCES
  ovpn.c
  ovpn_options.c
  
  LINK_LIBRARIES ${PICOTLS_LINK_LIBRARIES} ${OPENSSL_LIBRARIES}
  
  MULTIARCH_SOURCES
  ovpn_node.c
)
```

## 测试

### 单元测试（建议添加）

```c
// 测试 Picotls 上下文初始化
void test_picotls_init(void);

// 测试证书加载
void test_certificate_loading(void);

// 测试错误处理
void test_error_handling(void);
```

### 集成测试

1. **基本初始化测试**
   ```bash
   vpp# ovpn enable port 1194
   vpp# show ovpn
   vpp# ovpn disable
   ```

2. **证书加载测试**
   ```bash
   vpp# ovpn enable \
     ca-cert /etc/openvpn/ca.crt \
     server-cert /etc/openvpn/server.crt \
     server-key /etc/openvpn/server.key
   ```

3. **错误场景测试**
   - 文件不存在
   - 文件权限问题
   - 证书格式错误
   - 密钥不匹配

## 参考资料

- [Picotls 文档](https://github.com/h2o/picotls)
- [OpenVPN 协议](https://openvpn.net/community-resources/openvpn-protocol/)
- [VPP UDP 插件示例](https://github.com/FDio/vpp/tree/master/src/vnet/udp)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)

