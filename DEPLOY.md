# Veil SDK 部署指南

## 项目结构说明

```
github.com/hack007x/veil/
│
├── veil.go                        ✅ 公开 — SDK 对外 API 入口
├── options.go                     ✅ 公开 — 配置选项
├── go.mod                         ✅ 公开 — Go module 定义
├── .gitignore
├── README.md                      ✅ 公开 — 中文文档
├── README_EN.md                   ✅ 公开 — 英文文档
│
├── engine/
│   ├── interface.go               ✅ 公开 — Scanner 接口定义 + 注册机制
│   └── default.go                 ✅ 公开 — 默认引擎(桥接到 internal)
│
├── template/
│   └── models.go                  ✅ 公开 — 数据结构(用户需要这些类型)
│
├── parser/
│   └── parser.go                  ✅ 公开 — 模板解析器
│
├── probe/
│   └── probe.go                   ✅ 公开 — 存活探测
│
├── output/
│   └── output.go                  ✅ 公开 — 输出报告
│
├── validator/
│   └── validator.go               ✅ 公开 — 模板校验
│
├── internal/                      🔒 受保护 — Go 语言级别限制，外部项目无法 import
│   ├── runner/runner.go           🔒 核心 — 扫描引擎
│   ├── matcher/matcher.go         🔒 核心 — 匹配器
│   ├── extractor/extractor.go     🔒 核心 — 值提取
│   ├── resolver/resolver.go       🔒 核心 — 变量解析
│   ├── httpclient/client.go       🔒 核心 — HTTP 客户端
│   └── oob/oob.go                 🔒 核心 — OOB 回调
│
├── cmd/veil/
│   └── main.go                    ✅ 公开 — CLI 命令行工具
│
├── examples/
│   ├── basic/main.go              ✅ 公开 — 基础示例
│   └── advanced/main.go           ✅ 公开 — 高级示例
│
└── veil_poc/examples/             ✅ 公开 — 示例 POC 模板
```

### 关于 `internal/` 目录

Go 语言有一个内置规则：`internal/` 目录下的包只能被同一 module 的代码 import。
外部用户 `go get github.com/hack007x/veil` 后：

- ✅ 可以 import: `veil`, `veil/engine`, `veil/template`, `veil/parser` 等
- ❌ 无法 import: `veil/internal/runner`, `veil/internal/matcher` 等

**代码全部在 GitHub 上，但核心逻辑被 Go 的 internal 机制保护，别人看得到但引用不了。**

---

## 一步一步上传 GitHub

### 第 0 步：前置准备

确保你已经安装了 Git 和 Go：

```bash
git --version    # 需要 git 2.x+
go version       # 需要 go 1.21+
```

### 第 1 步：清空 GitHub 仓库（如果已有旧内容）

如果 https://github.com/hack007x/veil 已经有旧代码，先备份再清空：

```bash
# 如果仓库已有内容，先 clone 下来备份
git clone https://github.com/hack007x/veil.git veil-backup
```

### 第 2 步：解压 SDK 到本地

把我给你的 `veil-sdk.zip` 解压到一个干净目录：

```bash
# 解压
unzip veil-sdk.zip -d veil-project
cd veil-project
```

### 第 3 步：初始化 Git 仓库

```bash
# 初始化
git init

# 设置远程仓库
git remote add origin https://github.com/hack007x/veil.git
```

### 第 4 步：验证编译

```bash
# 确保所有包能编译
go build ./...

# 编译 CLI 二进制
go build -o veil ./cmd/veil/

# 测试运行
./veil -version
./veil -h
```

如果编译有问题，检查 Go 版本是否 >= 1.21。

### 第 5 步：提交并推送

```bash
# 添加所有文件
git add .

# 提交
git commit -m "feat: initial release - veil v1.0.0 vulnerability scanner SDK"

# 推送到 GitHub（如果仓库已有内容，用 --force）
git branch -M main
git push -u origin main

# 如果报错说远程有内容，用：
# git push -u origin main --force
```

### 第 6 步：打 Tag（让 go get 能识别版本）

```bash
git tag v1.0.0
git push origin v1.0.0
```

### 第 7 步：验证 go get

在另一个目录创建一个测试项目验证：

```bash
mkdir ~/test-veil && cd ~/test-veil
go mod init test-veil

# 创建测试文件
cat > main.go << 'EOF'
package main

import (
    "fmt"
    "github.com/hack007x/veil"
)

func main() {
    v := veil.New(veil.DefaultOptions())
    fmt.Println("Engine:", v.EngineName())
    fmt.Println("Version:", v.EngineVersion())
}
EOF

# 拉取并运行
go mod tidy
go run main.go
```

应该输出：

```
Engine: veil-default
Version: 1.0.0
```

---

## 验证 internal 保护生效

在测试项目中尝试 import 核心包，应该报错：

```go
// 这行会编译失败！
import "github.com/hack007x/veil/internal/runner"
```

报错信息：

```
use of internal package github.com/hack007x/veil/internal/runner not allowed
```

✅ 这说明保护生效了。

---

## 未来：接入私有增强引擎

当你以后开发了更强的私有引擎，创建一个私有仓库 `github.com/hack007x/veil-engine-pro`：

```go
// github.com/hack007x/veil-engine-pro/engine.go
package veilpro

import "github.com/hack007x/veil/engine"

func init() {
    engine.Use(&ProEngine{})
}

type ProEngine struct{}

func (e *ProEngine) Name() string    { return "veil-pro" }
func (e *ProEngine) Version() string { return "2.0.0" }
func (e *ProEngine) Scan(...) ...    { /* 更强的实现 */ }
```

授权用户只需加一行 import：

```go
import _ "github.com/hack007x/veil-engine-pro"  // 自动替换引擎
```

API 完全不变，底层引擎自动升级。
