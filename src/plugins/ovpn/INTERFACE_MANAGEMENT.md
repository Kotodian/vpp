# OpenVPN 接口管理文档

## 概述

本文档描述了 OpenVPN 插件的接口管理功能，包括 OpenVPN device class 的创建、接口的创建/删除以及 IP 地址的配置。

## OpenVPN Device Class

### 设备类定义

OpenVPN device class 在 `ovpn_if.c` 中定义：

```c
VNET_DEVICE_CLASS (ovpn_device_class) = {
  .name = "OpenVPN",
  .format_device_name = format_ovpn_if_name,
  .format_device = format_ovpn_if,
  .admin_up_down_function = ovpn_if_admin_up_down,
  .tx_function = ovpn_if_tx,
};
```

### 设备类特性

- **设备名称**: "OpenVPN"
- **接口命名**: 支持自定义名称（如 `tun0`, `tap0`），或自动生成 `ovpn0`, `ovpn1`, `ovpn2`...
- **模式支持**: 
  - TUN (Layer 3 / IP) - 默认
  - TAP (Layer 2 / Ethernet)
- **MTU**: 可配置（默认 1420）
- **管理功能**: 支持 admin up/down
- **TX 功能**: 数据包发送（待完全实现加密）

## 数据结构

### OpenVPN 接口实例 (ovpn_if_t)

```c
typedef struct ovpn_if_t_ {
  u32 dev_instance;      // 设备实例 ID
  u32 user_instance;     // 用户实例计数器
  u32 sw_if_index;       // 软件接口索引
  u32 hw_if_index;       // 硬件接口索引
  
  /* 接口名称 */
  u8 *name;              // 自定义接口名称（如 "tun0"）
  
  /* 接口配置 */
  ip_address_t local_addr;   // 本地 IP 地址
  ip_address_t remote_addr;  // 远程 IP 地址
  u16 local_port;            // 本地端口
  u16 remote_port;           // 远程端口
  
  /* 接口标志 */
  u8 is_tun;   // TUN (IP) 或 TAP (Ethernet) 模式
  u8 is_ipv6;  // IPv4 或 IPv6
} ovpn_if_t;
```

### OpenVPN 接口主结构 (ovpn_if_main_t)

```c
typedef struct ovpn_if_main_t_ {
  ovpn_if_t *ovpn_ifs;  // OpenVPN 接口池
  
  /* 哈希表: sw_if_index -> ovpn_if 索引 */
  uword *ovpn_if_index_by_sw_if_index;
  
  /* 便捷指针 */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ovpn_if_main_t;
```

## API 函数

### 1. 创建接口

```c
int ovpn_if_create (vlib_main_t *vm, u8 *name, u8 is_tun, u16 mtu,
                    u32 *sw_if_indexp);
```

**参数**:
- `vm`: VPP 主结构
- `name`: 接口名称（u8 vector，如 "tun0"）。如果为 NULL 或空，自动生成 "ovpn<N>"
- `is_tun`: 1 = TUN 模式（L3 IP 隧道）, 0 = TAP 模式（L2 以太网桥接）
- `mtu`: 接口 MTU 值（推荐：TUN=1420, TAP=1500）
- `sw_if_indexp`: 输出参数，返回创建的接口索引

**返回值**: 0 成功, < 0 失败

**功能**:
1. 从池中分配接口结构
2. 存储或生成接口名称
3. 生成 MAC 地址（TAP 模式）
4. 注册硬件/以太网接口
5. 重命名硬件接口为自定义名称
6. 设置指定的 MTU 值
7. 自动启用接口（admin up）
8. 添加到哈希表

### 2. 删除接口

```c
int ovpn_if_delete (vlib_main_t *vm, u32 sw_if_index);
```

**参数**:
- `vm`: VPP 主结构
- `sw_if_index`: 要删除的接口索引

**返回值**: 0 成功, < 0 失败

**功能**:
1. 禁用接口（admin down）
2. 删除硬件接口
3. 从哈希表移除
4. 释放接口名称内存
5. 释放池元素

### 3. 设置本地地址

```c
int ovpn_if_set_local_addr (u32 sw_if_index, ip_address_t *addr);
```

**功能**: 设置接口的本地 IP 地址（用于 OpenVPN 隧道端点）

### 4. 设置远程地址

```c
int ovpn_if_set_remote_addr (u32 sw_if_index, ip_address_t *addr);
```

**功能**: 设置接口的远程 IP 地址（用于 OpenVPN 隧道端点）

## CLI 命令

### 1. 创建 OpenVPN 接口

```bash
create ovpn interface name <name> [tun|tap] [mtu <size>]
```

**参数**:
- `name`: 接口名称（字符串，如 "tun0", "tap0"）
- `tun`: TUN 模式（Layer 3 IP 隧道，默认）
- `tap`: TAP 模式（Layer 2 以太网桥接）
- `mtu`: MTU 大小（可选，默认 1420）

**示例**:

```bash
# 创建 TUN 模式接口（默认 MTU）
vpp# create ovpn interface name tun0 tun
Created OpenVPN interface: tun0 (sw_if_index 1)

# 创建 TAP 模式接口并指定 MTU
vpp# create ovpn interface name tap0 tap mtu 1500
Created OpenVPN interface: tap0 (sw_if_index 2)

# 创建自定义 MTU 的 TUN 接口
vpp# create ovpn interface name vpn0 tun mtu 1380
Created OpenVPN interface: vpn0 (sw_if_index 3)
```

### 2. 删除 OpenVPN 接口

```bash
delete ovpn interface <interface>
```

**参数**:
- `interface`: 接口名称或索引

**示例**:

```bash
vpp# delete ovpn interface ovpn0
Deleted OpenVPN interface

vpp# delete ovpn interface sw_if_index 1
Deleted OpenVPN interface
```

### 3. 通过 ovpn enable 自动创建接口

```bash
ovpn enable dev <name> [mode tun|tap] [mtu <size>] server-addr <ip>/<len> ...
```

**功能**: 
- 自动创建 OpenVPN 接口（TUN 或 TAP 模式）
- 支持自定义 MTU
- 自动设置 IP 地址
- 启用接口

**参数**:
- `dev <name>`: 接口名称（如 "tun0", "tap0"）
- `mode tun|tap`: 接口模式（可选，默认 tun）
- `mtu <size>`: MTU 大小（可选，默认 1420）
- `server-addr <ip>/<len>`: 服务器 IP 地址和掩码

**示例**:

```bash
# 自动创建 TUN 接口并配置 IPv4 地址（默认 MTU）
vpp# ovpn enable port 1194 dev tun0 server-addr 10.8.0.1/24 \
  pool-start 10.8.0.10 pool-end 10.8.0.250
Loaded CA certificate from ...
Initialized picotls context
Created OpenVPN interface tun0 (sw_if_index 1, mode TUN, mtu 1420)
Set interface address: 10.8.0.1/24
Registered UDP port 1194 (IPv4/IPv6)
OpenVPN enabled on port 1194

# 创建 TAP 接口并自定义 MTU
vpp# ovpn enable port 1194 dev tap0 mode tap mtu 1500 server-addr 10.8.0.1/24
Created OpenVPN interface tap0 (sw_if_index 1, mode TAP, mtu 1500)
Set interface address: 10.8.0.1/24
OpenVPN enabled on port 1194

# 自动创建接口并配置 IPv6 地址
vpp# ovpn enable port 1194 dev tun0 server-addr fd00::1/64
Created OpenVPN interface tun0 (sw_if_index 1, mode TUN, mtu 1420)
Set interface address: fd00::1/64
OpenVPN enabled on port 1194
```

## 集成到主 OpenVPN 配置

### ovpn_options_t 扩展

在 `ovpn_options.h` 中添加了 `sw_if_index` 字段：

```c
typedef struct ovpn_options_t_ {
  // ... 其他字段 ...
  char *dev_name;
  u32 sw_if_index;     // 软件接口索引
  u16 mtu;             // MTU 大小
  u8 is_tun;           // TUN (1) 或 TAP (0) 模式
  fib_prefix_t server_addr;
  // ... 其他字段 ...
} ovpn_options_t;
```

### 自动创建和配置流程

在 `ovpn_enable_command_fn()` 中：

1. **创建接口**（如果指定了 `dev`）:
   ```c
   ovpn_if_create(vm, dev_name, is_tun, mtu, &sw_if_index);
   ```

2. **设置 IP 地址**（如果指定了 `server-addr`）:
   ```c
   // IPv4
   ip4_add_del_interface_address(vm, sw_if_index, 
                                  &server_addr.fp_addr.ip4,
                                  server_addr.fp_len, 0);
   
   // IPv6
   ip6_add_del_interface_address(vm, sw_if_index,
                                  &server_addr.fp_addr.ip6,
                                  server_addr.fp_len, 0);
   ```

3. **存储接口索引**:
   ```c
   omp->options.sw_if_index = sw_if_index;
   ```

## 接口特性

### MAC 地址生成

自动生成的 MAC 地址格式：
```
02:fe:XX:XX:XX:XX
```

其中：
- `02`: 本地管理位（locally administered）
- `fe`: 固定前缀
- `XX:XX:XX:XX`: 基于 `dev_instance` 生成

### MTU 设置

**可配置 MTU**: 

- **TUN 模式推荐**: 1420 字节（为 OpenVPN 头部预留空间）
- **TAP 模式推荐**: 1500 字节（标准以太网 MTU）
- **默认值**: 1420 字节（如果未指定）

原因: OpenVPN 协议开销需要预留空间以避免 IP 分片
- 以太网 MTU: 1500
- IP 头: 20 (IPv4) 或 40 (IPv6)
- UDP 头: 8
- OpenVPN 头: ~30-50
- 剩余可用: ~1420

可以通过标准 VPP 命令修改:
```bash
vpp# set interface mtu 1400 ovpn0
```

### 接口状态

创建后自动 admin up:
```bash
vpp# show interface ovpn0
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
ovpn0                             1      up          1420/0/0/0
```

## 使用场景

### 场景 1: 手动创建接口

```bash
# 1. 创建接口
vpp# create ovpn interface name vpn0 tun

# 2. 设置 IP 地址
vpp# set interface ip address ovpn0 10.8.0.1/24

# 3. 启用接口（已自动启用）
vpp# show interface ovpn0
```

### 场景 2: 通过 ovpn enable 自动创建

```bash
# 一条命令完成所有配置
vpp# ovpn enable port 1194 \
  dev tun0 \
  server-addr 10.8.0.1/24 \
  pool-start 10.8.0.10 \
  pool-end 10.8.0.250 \
  ca-cert /etc/openvpn/ca.crt \
  server-cert /etc/openvpn/server.crt \
  server-key /etc/openvpn/server.key
```

### 场景 3: IPv6 配置

```bash
vpp# ovpn enable port 1194 \
  dev tun0 \
  server-addr fd00::1/64 \
  pool-start fd00::10 \
  pool-end fd00::250
```

### 场景 4: 查看和管理

```bash
# 查看所有接口
vpp# show interface

# 查看特定接口详情
vpp# show interface ovpn0

# 查看 IP 地址
vpp# show interface address ovpn0

# 查看 OpenVPN 配置
vpp# show ovpn
```

## 高级功能（待实现）

### 1. 动态接口创建

- [ ] 为每个客户端连接创建独立接口
- [ ] 支持接口池管理
- [ ] 自动分配 IP 地址

### 2. 接口统计

- [ ] 接收/发送字节计数
- [ ] 错误计数
- [ ] 丢包统计

### 3. QoS 和流量整形

- [ ] 支持速率限制
- [ ] 优先级队列
- [ ] 流量分类

### 4. TAP 模式完整支持

- [ ] 桥接模式
- [ ] VLAN 支持
- [ ] MAC 学习

## 故障排查

### 问题 1: 接口创建失败

**症状**:
```
failed to create OpenVPN interface
```

**可能原因**:
- 内存不足
- 设备类未注册
- 接口池已满

**解决方法**:
```bash
# 检查设备类
vpp# show hardware

# 检查内存
vpp# show memory
```

### 问题 2: IP 地址设置失败

**症状**:
```
Set interface address failed
```

**可能原因**:
- 地址格式错误
- 地址冲突
- 接口不存在

**解决方法**:
```bash
# 验证接口存在
vpp# show interface ovpn0

# 检查现有地址
vpp# show interface address

# 手动设置地址
vpp# set interface ip address ovpn0 10.8.0.1/24
```

### 问题 3: 接口无法 ping 通

**检查清单**:
1. 接口是否 up
   ```bash
   vpp# show interface ovpn0
   ```

2. IP 地址是否正确设置
   ```bash
   vpp# show interface address ovpn0
   ```

3. 路由是否正确
   ```bash
   vpp# show ip fib
   ```

4. OpenVPN 是否启用
   ```bash
   vpp# show ovpn
   ```

## 性能考虑

### 内存使用

每个接口约占用:
- `ovpn_if_t` 结构: ~64 字节
- 硬件接口结构: ~256 字节
- 总计: ~320 字节/接口

### CPU 开销

- 接口创建: 一次性操作，开销可忽略
- TX 函数: 每个数据包调用一次
- 管理操作: 很少调用

## 测试

### 基本测试

```bash
# 1. 创建接口
vpp# create ovpn interface name test tun

# 2. 验证接口存在
vpp# show interface test

# 3. 设置地址
vpp# set interface ip address test 10.10.10.1/24

# 4. Ping 测试（需要对端）
vpp# ping 10.10.10.2

# 5. 删除接口
vpp# delete ovpn interface test
```

### 压力测试

```bash
# 创建多个接口
for i in {0..99}; do
  vpp# create ovpn interface name vpn$i tun
done

# 检查资源使用
vpp# show memory
vpp# show interface
```

## 参考代码

### 其他 VPP 设备类示例

- TAP 设备: `src/vnet/devices/tap/tap.c`
- Pipe 设备: `src/vnet/devices/pipe/pipe.c`
- VXLAN 隧道: `src/vnet/vxlan/vxlan.c`
- IPsec 隧道: `src/vnet/ipsec/ipsec_tun.c`

## 相关文档

- [VPP Interface 文档](https://fd.io/docs/vpp/master/interfacing/index.html)
- [VPP Device Class API](https://fd.io/docs/vpp/master/reference/api/vnet/interface.html)
- [OpenVPN 协议](https://openvpn.net/community-resources/openvpn-protocol/)

