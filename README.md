# OpenClaw Enterprise Security Plugin

企业级安全插件：默认拒绝策略 + 审计日志 + 数据敏感度分流。

## 安装

```bash
# 从 NPM 安装
openclaw plugin add @xuan599/openclaw-security-plugin

# 或从源码构建
cd packages/openclaw-enterprise-security
npm install && npm run build
openclaw plugin add ./packages/openclaw-enterprise-security
```

**要求**: OpenClaw >= 2026.3.28

## 配置

在 `openclaw.json` 中添加：

```json5
{
  "plugins": {
    "entries": {
      "enterprise-security": {
        "enabled": true,
        "config": {
          // --- 策略配置 ---
          "policy": {
            "mode": "deny",              // "deny" = 默认拒绝 | "allow" = 默认放行
            "allowTools": [
              "read",                     // 允许读文件
              "write",                    // 允许写文件
              "search",                   // 允许搜索
              "web_fetch"                 // 允许网页抓取
            ],
            "denyTools": [
              "exec",                     // 禁止执行命令
              "full",                     // 禁止完整 shell
              "shell",
              "bash"
            ],
            "allowPatterns": [
              "file_*",                   // 允许所有 file_ 开头的工具
              "mcp__*"                    // 允许所有 MCP 工具
            ]
          },

          // --- 敏感度配置 ---
          "sensitivity": {
            "s3Patterns": [
              "密码", "私钥", "机密", "绝密",
              "secret_key", "api_key", "access_token", "password"
            ],
            "s2Patterns": [
              "内部", "confidential", "薪酬", "财务报表",
              "客户名单", "合同"
            ],
            "scanArguments": true         // 扫描工具参数（不只是 prompt）
          },

          // --- 审计配置 ---
          "audit": {
            "logDir": "./logs"            // 日志目录，默认 ./logs
          },

          // --- 设备配对安全 ---
          "pairing": {
            "allowInsecureAuth": false,   // 必须为 false，否则阻止所有配对操作
            "pairingRequired": true,      // 建议启用：强制设备配对认证
            "approvedDevicesOnly": true   // 建议启用：仅允许已审批设备
          }
        }
      }
    }
  }
}
```

## 三个核心功能

### 1. 默认拒绝策略

所有工具调用默认被阻止，除非在白名单中。

```jsonc
// 只允许这三个工具，其余全部阻止
"policy": {
  "mode": "deny",
  "allowTools": ["read", "write", "search"]
}
```

优先级：`denyTools` > `allowTools` > `allowPatterns` > `mode`

### 2. 审计日志

每次工具调用自动记录 JSONL 日志。

```bash
# 查看今天的审计日志
cat logs/audit-2026-04-08.jsonl

# 查看被阻止的调用
cat logs/audit-2026-04-08.jsonl | grep '"blocked"'

# 查看敏感数据相关调用
cat logs/audit-2026-04-08.jsonl | grep '"S[23]"'
```

日志格式（每行一条）：

```json
{"ts":"2026-04-08T12:00:00.000Z","tool":"exec","decision":"blocked","reason":"Tool \"exec\" is in the explicit deny list","user":"zhangsan","sessionId":"sess-abc123"}
{"ts":"2026-04-08T12:00:01.000Z","tool":"read","decision":"allowed","user":"zhangsan","sessionId":"sess-abc123"}
{"ts":"2026-04-08T12:00:02.000Z","tool":"web_fetch","decision":"blocked","reason":"S3: Sensitive data detected, forced local routing","sensitivity":"S3","user":"zhangsan"}
```

### 3. 数据敏感度分流

自动检测请求中的敏感数据，按三级分类：

| 级别 | 含义 | 行为 | 示例 |
|------|------|------|------|
| **S1** | 公开数据 | 正常放行 | "今天天气怎么样" |
| **S2** | 内部数据 | 放行但记录审计 | "内部员工薪酬数据" |
| **S3** | 敏感数据 | **阻止云端工具**，强制本地 | "密码是 abc123"、"身份证号" |

S3 数据会阻止 `web_fetch`、`web_search`、`http_request` 等可能外发数据的工具。

## 快速开始

**最小配置（推荐起步）**：

```json5
{
  "plugins": {
    "entries": {
      "enterprise-security": {
        "enabled": true,
        "config": {
          "policy": {
            "mode": "deny",
            "allowTools": ["read", "write", "search"],
            "denyTools": ["exec", "full", "shell", "bash"]
          }
        }
      }
    }
  }
}
```

**运行测试**：

```bash
cd packages/openclaw-enterprise-security
npm install
npm test
```

## 自定义敏感词

根据你的行业添加特定敏感词：

```jsonc
"sensitivity": {
  "s3Patterns": [
    // 通用
    "密码", "私钥", "api_key", "secret_key",
    // 医疗
    "病历", "诊断", "患者信息",
    // 金融
    "银行卡", "信用卡", "交易记录",
    // 正则匹配（身份证号）
    "\\b\\d{17}[\\dXx]\\b"
  ]
}
```

## 常见问题

**Q: 插件加载后所有工具都不能用了？**

`mode: "deny"` 是默认拒绝，你需要在 `allowTools` 中列出所有允许的工具。先检查 `openclaw.json` 配置。

**Q: 怎么临时关闭安全策略？**

```json
"enterprise-security": { "enabled": false }
```

**Q: 审计日志文件会越来越大怎么办？**

v1 没有日志轮转。用系统工具处理：

```bash
# 按天归档
find logs/ -name "audit-*.jsonl" -mtime +30 -delete
```

**Q: 敏感度检测误报太多？**

减少 `s3Patterns` 和 `s2Patterns` 中的模式，只保留你真正关心的关键词。

## 架构

```
插件启动 → SecurityChecks.runStartupChecks()
                │
                ├─ 版本检查：< 2026.3.28 → 拒绝启动
                ├─ 配对检查：allowInsecureAuth=true → 拒绝启动
                └─ 安全警告：pairingRequired=false → 警告

用户请求 → OpenClaw Gateway
    │
    ▼ before_tool_call Hook
┌───────────────────────────────┐
│  0. Pairing Guard             │ → 配对工具 + 不安全配置? → 阻止
│  1. PolicyEngine.check()      │ → block? → 阻止 + 审计
│  2. SensitivityRouter         │ → S3 + 云端工具? → 阻止 + 审计
│  3. AuditLogger.log()         │ → 记录通过/阻止
└───────────────────────────────┘
    │
    ▼ 放行
工具正常执行
```

## 安全公告

### CVE-2026-33579 及相关漏洞防护

本插件针对 2026 年 OpenClaw 设备配对相关的 8 个 CVE 提供以下防护：

| CVE | 严重性 | 防护措施 |
|-----|--------|----------|
| CVE-2026-33579 | HIGH (CVSS 8.1-9.8) | 启动时版本检查 + 配对工具拦截 |
| CVE-2026-32922 | Critical | 启动时版本检查 |
| CVE-2026-28472 | Critical | 启动时版本检查 |
| CVE-2026-32001 | Auth bypass | 启动时版本检查 |
| CVE-2026-32057 | Auth bypass | 启动时版本检查 |
| **CVE-2026-32034** | Auth bypass | `allowInsecureAuth` 配置检查 + 配对工具拦截 |
| CVE-2026-28446 | Auth bypass | 启动时版本检查 |
| CVE-2026-28450 | Auth bypass | 启动时版本检查 |

**防护机制**：

1. **启动时强制版本检查**：若 OpenClaw 核心版本 < 2026.3.28，插件直接拒绝启动
2. **不安全配置阻断**：若 `allowInsecureAuth` 设为 `true`，插件拒绝启动
3. **配对工具运行时拦截**：所有 pairing 相关工具调用在 `allowInsecureAuth` 未显式设为 `false` 时被阻止

**建议**：
- 确保 OpenClaw 核心已升级至 2026.3.28 或更高版本
- 在 `openclaw.json` 中显式设置 `pairing.allowInsecureAuth: false`
- 生产环境启用 `pairingRequired` 和 `approvedDevicesOnly`
用户请求 → OpenClaw Gateway
    │
    ▼ before_tool_call Hook
┌───────────────────────────┐
│  1. PolicyEngine.check()  │ → block? → 阻止 + 审计
│  2. SensitivityRouter     │ → S3 + 云端工具? → 阻止 + 审计
│  3. AuditLogger.log()     │ → 记录通过/阻止
└───────────────────────────┘
    │
    ▼ 放行
工具正常执行
```
