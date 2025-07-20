---
title: OnDemand2Api
emoji: 😻
colorFrom: red
colorTo: red
sdk: docker
pinned: false
---

# OpenAI OnDemand Adapter - Go版本

这是一个高性能的Go语言实现版本，将OpenAI API请求转换为OnDemand API调用，支持异步并发处理。

## 主要特性

### 🚀 性能优化
- **异步并发处理**：使用Goroutines和Channels实现高并发请求处理
- **连接池复用**：HTTP客户端连接复用，减少连接开销
- **内存优化**：高效的内存管理，避免内存泄漏
- **多阶段Docker构建**：最小化最终镜像大小

### 🔧 核心功能
- **API密钥管理**：支持多个API密钥的自动轮换和故障转移
- **会话管理**：智能维护OnDemand API会话状态，支持会话超时自动重置
- **流式响应**：支持Server-Sent Events (SSE)流式响应
- **模型映射**：灵活的OpenAI模型到OnDemand端点的映射
- **错误处理**：完善的错误处理和自动重试机制
- **健康检查**：内置健康检查端点

### 🛡️ 安全特性
- **API鉴权**：支持Authorization Bearer Token和X-API-KEY头部鉴权
- **只读文件系统**：Docker容器使用只读根文件系统提高安全性
- **资源限制**：Docker容器资源限制和安全配置

## 快速开始

### 环境要求
- Go 1.21+
- Docker & Docker Compose (可选)

### 本地运行

1. **克隆项目并安装依赖**
```bash
git clone <repository>
cd ondemand2api
go mod download
```

2. **设置环境变量**
```bash
export PRIVATE_KEY="your_private_key_here"
export ONDEMAND_APIKEYS="key1,key2,key3"
export PORT=7860  # 可选，默认7860
export GIN_MODE=release  # 可选：debug, release, test
```

3. **运行应用**
```bash
go run main.go
```

### Docker运行

1. **构建并运行**
```bash
# 构建镜像
docker build -t ondemand2api .

# 运行容器
docker run -p 7860:7860 \
  -e PRIVATE_KEY="your_private_key_here" \
  -e ONDEMAND_APIKEYS="key1,key2,key3" \
  ondemand2api
```

2. **使用Docker Compose**
```bash
# 编辑docker-compose.yml中的环境变量
# 然后运行：
docker-compose up -d
```

## API接口

### 聊天完成接口
```http
POST /v1/chat/completions
Authorization: Bearer your_private_key_here
Content-Type: application/json

{
  "model": "gpt-4o",
  "messages": [
    {"role": "user", "content": "Hello!"}
  ],
  "stream": false
}
```

### 模型列表接口
```http
GET /v1/models
Authorization: Bearer your_private_key_here
```

### 健康检查接口
```http
GET /
```

## 配置说明

### 环境变量

| 变量名 | 必需 | 默认值 | 说明 |
|--------|------|--------|------|
| `PRIVATE_KEY` | 是 | testofli | API访问密钥 |
| `ONDEMAND_APIKEYS` | 是 | - | OnDemand API密钥列表，逗号分隔 |
| `PORT` | 否 | 7860 | 服务端口 |
| `GIN_MODE` | 否 | release | Gin运行模式 |

### 支持的模型映射

| OpenAI模型 | OnDemand端点 |
|------------|--------------|
| o3 | predefined-openai-gpto3 |
| o3-mini | predefined-openai-gpto3-mini |
| gpt-4o | predefined-openai-gpt4o |
| gpt-4.1 | predefined-openai-gpt4.1 |
| deepseek-v3 | predefined-deepseek-v3 |
| deepseek-r1 | predefined-deepseek-r1 |
| claude-4-sonnet | predefined-claude-4-sonnet |
| gemini-2.5-pro | predefined-gemini-2.5-pro-preview |

## 性能特性

### 并发处理
- **Goroutines**：每个请求在独立的goroutine中处理
- **Channel通信**：使用带缓冲的channel处理流式响应
- **连接复用**：HTTP客户端自动复用连接
- **超时控制**：完善的上下文超时控制

### 内存管理
- **垃圾回收优化**：合理的对象生命周期管理
- **缓冲区复用**：高效的内存缓冲区使用
- **资源自动释放**：defer语句确保资源及时释放

### 错误处理
- **分级重试**：根据错误类型进行智能重试
- **熔断机制**：自动检测和恢复故障的API密钥
- **日志记录**：详细的操作日志和错误追踪

## 监控和日志

### 日志输出
应用使用结构化日志输出，包含：
- 请求处理信息
- API密钥使用状态
- 会话管理状态
- 错误和异常信息

### 健康检查
- HTTP健康检查端点：`GET /`
- Docker健康检查：自动检查服务可用性
- 返回API密钥池状态

## 与Python版本的对比

| 特性 | Python版本 | Go版本 |
|------|------------|--------|
| **性能** | 中等 | 高 |
| **并发处理** | 线程池 | Goroutines |
| **内存使用** | 较高 | 较低 |
| **启动时间** | 较慢 | 快 |
| **资源占用** | 高 | 低 |
| **并发能力** | 受GIL限制 | 原生并发 |
| **部署大小** | 大 | 小 |

## 开发说明

### 项目结构
```
.
├── main.go                 # 主应用文件
├── go.mod                  # Go模块定义
├── go.sum                  # 依赖锁定文件
├── Dockerfile              # Docker构建文件
├── docker-compose.yml      # Docker Compose配置
└── README.md               # 项目文档
```

### 关键组件

1. **KeyManager**: API密钥管理器
   - 自动轮换密钥
   - 故障检测和恢复
   - 会话状态管理

2. **HTTP处理器**: 
   - Gin框架路由
   - 中间件鉴权
   - 流式响应处理

3. **并发控制**:
   - Context超时控制
   - Goroutine池管理
   - Channel通信

## 故障排查

### 常见问题

1. **端口占用**
```bash
# 检查端口占用
lsof -i :7860
# 或使用不同端口
export PORT=8080
```

2. **API密钥问题**
```bash
# 检查环境变量
echo $ONDEMAND_APIKEYS
# 查看日志输出的密钥状态
```

3. **内存使用**
```bash
# 监控容器资源使用
docker stats ondemand2api
```

## 许可证

本项目基于原Python项目进行Go语言重构，保持相同的功能特性并增强了性能和并发能力。