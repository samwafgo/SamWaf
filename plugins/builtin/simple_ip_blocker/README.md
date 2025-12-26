# Simple IP Blocker 插件

## 📝 插件简介

这是一个简单的IP屏蔽插件，用于演示 SamWaf 插件系统的基本功能。

**主要功能**:
- 屏蔽指定的IP地址
- 支持自定义屏蔽原因
- 支持动态添加/移除屏蔽IP
- 同时实现 IPFilterPlugin 和 WafCheckPlugin 接口

**示例场景**: 屏蔽 8.8.8.8（Google DNS）的访问请求

---

## 🚀 快速开始

### 1. 编译插件

**Linux/Mac**:
```bash
cd plugins/builtin/simple_ip_blocker
chmod +x build.sh
./build.sh
```

**Windows**:
```cmd
cd plugins\builtin\simple_ip_blocker
build.bat
```

### 2. 配置插件

**方式一: 通过配置文件**

编辑 `conf/plugins.yml`:
```yaml
plugins:
  enabled: true
  
  list:
    - id: "simple_ip_blocker_001"
      name: "Simple IP Blocker"
      description: "屏蔽指定的IP地址"
      type: "ip_filter"
      version: "1.0.0"
      enabled: true
      binary_path: "./data/plugins/binaries/simple_ip_blocker"
      priority: 100
      
      groups:
        - "pre_check"      # 在预检查阶段执行
        - "ip_filter"      # 属于IP过滤组
      
      params:
        blocked_ips:       # 要屏蔽的IP列表
          - "8.8.8.8"
          - "8.8.4.4"
        block_reason: "DNS服务器 - 禁止访问"
```

**方式二: 通过API**

```bash
# 添加插件配置
curl -X POST http://localhost:26666/api/v1/wafplugin/add \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_id": "simple_ip_blocker_001",
    "name": "Simple IP Blocker",
    "description": "屏蔽指定的IP地址",
    "type": "ip_filter",
    "version": "1.0.0",
    "enabled": 1,
    "binary_path": "./data/plugins/binaries/simple_ip_blocker",
    "priority": 100,
    "groups": "[\"pre_check\",\"ip_filter\"]",
    "params": "{\"blocked_ips\":[\"8.8.8.8\",\"8.8.4.4\"],\"block_reason\":\"DNS服务器 - 禁止访问\"}"
  }'
```

### 3. 启动 SamWaf

```bash
cd ../../../
go run main.go
```

插件将自动加载并开始工作！

---

## 🔧 配置说明

### 插件参数

| 参数名 | 类型 | 必填 | 说明 | 示例 |
|--------|------|------|------|------|
| `blocked_ips` | 数组 | 否 | 要屏蔽的IP列表 | `["8.8.8.8", "1.1.1.1"]` |
| `block_reason` | 字符串 | 否 | 屏蔽原因 | `"安全策略禁止访问"` |

### 插件分组

建议将此插件配置在以下分组：

- **pre_check**: 在所有检测之前执行，实现快速过滤
- **ip_filter**: IP过滤阶段，与其他IP过滤器一起工作

---

## 📋 工作原理

### 流程图

```
客户端请求
    ↓
[WAF接收请求]
    ↓
[pre_check 插件组] ← Simple IP Blocker 在此执行
    ↓
检查IP是否在屏蔽列表？
    ├─ 是 → 返回拦截（Allowed: false, RiskLevel: 8）
    │        ↓
    │     [WAF拦截请求]
    │        ↓
    │     返回403
    │
    └─ 否 → 返回允许（Allowed: true, RiskLevel: 0）
            ↓
         [继续后续检测]
            ↓
         转发到后端
```

### 检测逻辑

```go
1. 接收请求中的IP地址
2. 查找IP是否在屏蔽列表中
3. 如果在列表中：
   - 返回 Allowed: false
   - 返回 RiskLevel: 8（高风险）
   - 返回原因
4. 如果不在列表中：
   - 返回 Allowed: true
   - 返回 RiskLevel: 0
```

---

## 🧪 测试

### 运行测试

```bash
cd plugins/builtin/simple_ip_blocker
go test -v
```

### 测试覆盖率

```bash
go test -cover
```

### 性能测试

```bash
go test -bench=. -benchmem
```

### 测试用例

```bash
# 测试屏蔽IP
curl http://localhost:8080 -H "X-Forwarded-For: 8.8.8.8"
# 预期: 403 Forbidden

# 测试正常IP
curl http://localhost:8080 -H "X-Forwarded-For: 192.168.1.1"
# 预期: 正常响应
```

---

## 📊 插件接口

### 实现的接口

#### 1. Plugin 基础接口

```go
type Plugin interface {
    Name() string                                         // 返回 "Simple IP Blocker"
    Version() string                                      // 返回 "1.0.0"
    Type() string                                         // 返回 "ip_filter"
    Init(config map[string]interface{}) error            // 初始化
    Shutdown() error                                      // 关闭
    HealthCheck(ctx context.Context) error               // 健康检查
}
```

#### 2. IPFilterPlugin 接口

```go
type IPFilterPlugin interface {
    Plugin
    Filter(ctx context.Context, req *IPFilterRequest) (*IPFilterResponse, error)
}

// 请求
type IPFilterRequest struct {
    IP          string
    RequestPath string
    UserAgent   string
}

// 响应
type IPFilterResponse struct {
    Allowed   bool   // 是否允许
    Reason    string // 原因
    RiskLevel int    // 风险等级 0-10
}
```

#### 3. WafCheckPlugin 接口

```go
type WafCheckPlugin interface {
    Plugin
    Check(ctx context.Context, req *WafCheckRequest) (*WafCheckResponse, error)
}

// 请求
type WafCheckRequest struct {
    RequestID   string
    IP          string
    Method      string
    URL         string
    Headers     map[string]string
}

// 响应
type WafCheckResponse struct {
    Allowed   bool
    Reason    string
    RiskLevel int
    Action    string // "allow" / "block" / "captcha"
}
```

---

## 🔍 日志示例

```
[Simple IP Blocker] 插件初始化中...
[Simple IP Blocker] 添加屏蔽IP: 8.8.8.8
[Simple IP Blocker] 添加屏蔽IP: 8.8.4.4
[Simple IP Blocker] 初始化完成，当前屏蔽 2 个IP

[Simple IP Blocker] 检查IP: 192.168.1.1
[Simple IP Blocker] ✅ 允许IP: 192.168.1.1

[Simple IP Blocker] 检查IP: 8.8.8.8
[Simple IP Blocker] ⛔ 屏蔽IP: 8.8.8.8, 原因: DNS服务器 - 禁止访问
```

---

## 🎯 使用场景

### 1. 屏蔽公共DNS服务器
```yaml
params:
  blocked_ips:
    - "8.8.8.8"      # Google DNS
    - "8.8.4.4"      # Google DNS
    - "1.1.1.1"      # Cloudflare DNS
    - "1.0.0.1"      # Cloudflare DNS
  block_reason: "禁止DNS服务器直接访问"
```

### 2. 屏蔽已知的恶意IP
```yaml
params:
  blocked_ips:
    - "1.2.3.4"
    - "5.6.7.8"
  block_reason: "已知恶意IP"
```

### 3. 临时屏蔽某个IP
```yaml
params:
  blocked_ips:
    - "10.20.30.40"
  block_reason: "临时屏蔽 - 异常行为"
```

---

## 🚧 限制与注意事项

### 当前限制

1. **未集成 go-plugin 框架**: 当前版本是示例实现，等待 go-plugin 集成
2. **静态IP列表**: 屏蔽IP列表在启动时加载，修改后需要重启插件
3. **内存存储**: IP列表存储在内存中，重启后需要重新加载

### 性能考虑

- **查找复杂度**: O(1) - 使用 map 存储，查找非常快
- **内存占用**: 每个IP约占 50-100 字节
- **并发安全**: 当前版本不支持并发修改（读取是安全的）

---


## 💬 问题反馈

如有问题或建议，请：
1. 查看插件日志
2. 运行测试用例
3. 提交 Issue

---

**插件版本**: v1.0.0  
**创建日期**: 2025-12-26  
**作者**: SamWaf Team  
**许可**: Apache

