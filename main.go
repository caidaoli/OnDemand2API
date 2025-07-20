package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

// 配置常量
const (
	BadKeyRetryInterval = 600 * time.Second // 10分钟
	SessionTimeout      = 600 * time.Second // 10分钟
	DefaultPort         = 7860
)

// Function Calling 提示模板
const functionCallPromptTemplate = `你可以使用以下工具来帮助你解决问题：

工具列表：

{{TOOLS_LIST}}

当你判断需要使用工具时，必须严格遵循以下格式：

1. 回答的第一行必须是：
FC_USE
没有任何前、尾随空格，全大写。

2. 然后，在回答的最后，请使用如下格式输出函数调用（使用 XML 语法）：

<function_call>
  <tool>tool_name</tool>
  <args>
    <key1>value1</key1>
    <key2>value2</key2>
  </args>
</function_call>

注意事项：
- 除非你确定需要调用工具，否则不要输出 FC_USE。
- 你只能调用一个工具。
- 保证输出的 XML 是有效的、严格符合上述格式。
- 不要随便更改格式。
- 你单回合只能调用一次工具。

现在请准备好遵循以上规范。`

// 全局变量
var (
	privateKey      string
	ondemandAPIKeys []string
	safeHeaders     = []string{"Authorization", "X-API-KEY"}
	ondemandAPIBase = "https://api.on-demand.io/chat/v1"
)

// HTTP客户端池和对象池
var (
	httpClientPool = &sync.Pool{
		New: func() interface{} {
			return &http.Client{
				Timeout: 60 * time.Second,
				Transport: &http.Transport{
					MaxIdleConns:        100,
					MaxIdleConnsPerHost: 10,
					IdleConnTimeout:     90 * time.Second,
					DisableKeepAlives:   false,
				},
			}
		},
	}
	// 预编译正则表达式
	toolRegex = regexp.MustCompile(`<tool>(.*?)</tool>`)
	argsRegex = regexp.MustCompile(`<args>([\s\S]*?)</args>`)
	argRegex  = regexp.MustCompile(`<(\w+)>(.*?)</(\w+)>`)
	// 字符串构建器池
	builderPool = &sync.Pool{
		New: func() interface{} {
			return &strings.Builder{}
		},
	}
)

// 模型映射
var modelMap = map[string]string{
	"o3-mini":         "predefined-openai-gpto3-mini",
	"o4-mini":         "predefined-openai-gpto4-mini",
	"gpt-4o":          "predefined-openai-gpt4o",
	"gpt-4.1":         "predefined-openai-gpt4.1",
	"gpt-4.1-mini":    "predefined-openai-gpt4.1-mini",
	"gpt-4o-mini":     "predefined-openai-gpt4o-mini",
	"deepseek-v3":     "predefined-deepseek-v3",
	"deepseek-r1":     "predefined-deepseek-r1",
	"claude-4-sonnet": "predefined-claude-4-sonnet",
	"claude-4-opus":   "predefined-claude-4-opus",
	"grok-4":          "predefined-xai-grok4",
}

// KeyStatus 表示API密钥的状态
type KeyStatus struct {
	Bad   bool      `json:"bad"`
	BadTS time.Time `json:"bad_ts"`
}

// KeyManager 管理API密钥的轮换和状态
type KeyManager struct {
	keyList        []string
	mu             sync.RWMutex
	keyStatus      map[string]*KeyStatus
	idx            int
	currentKey     string
	currentSession string
	lastUsedTime   time.Time
}

// NewKeyManager 创建新的密钥管理器
func NewKeyManager(keys []string) *KeyManager {
	km := &KeyManager{
		keyList:   make([]string, len(keys)),
		keyStatus: make(map[string]*KeyStatus),
	}
	copy(km.keyList, keys)

	for _, key := range keys {
		km.keyStatus[key] = &KeyStatus{}
	}

	return km
}

// displayKey 显示密钥的简化版本
func (km *KeyManager) displayKey(key string) string {
	if len(key) <= 10 {
		return key
	}
	return fmt.Sprintf("%s...%s", key[:6], key[len(key)-4:])
}

// Get 获取可用的API密钥
func (km *KeyManager) Get() string {
	km.mu.Lock()
	defer km.mu.Unlock()

	now := time.Now()

	// 检查会话是否超时
	if km.currentKey != "" && !km.lastUsedTime.IsZero() &&
		now.Sub(km.lastUsedTime) > SessionTimeout {
		log.Printf("【对话超时】上次使用时间: %s", km.lastUsedTime.Format("2006-01-02 15:04:05"))
		log.Printf("【对话超时】当前时间: %s", now.Format("2006-01-02 15:04:05"))
		log.Printf("【对话超时】超时%d分钟,切换新会话", int(SessionTimeout.Minutes()))
		km.currentKey = ""
		km.currentSession = ""
	}

	// 如果已有正在使用的key,继续使用
	if km.currentKey != "" {
		if !km.keyStatus[km.currentKey].Bad {
			log.Printf("【对话请求】【继续使用API KEY: %s】【状态:正常】", km.displayKey(km.currentKey))
			km.lastUsedTime = now
			return km.currentKey
		} else {
			// 当前key已标记为异常,需要切换
			km.currentKey = ""
			km.currentSession = ""
		}
	}

	// 选择新的key
	total := len(km.keyList)
	for i := 0; i < total; i++ {
		key := km.keyList[km.idx]
		km.idx = (km.idx + 1) % total
		status := km.keyStatus[key]

		if !status.Bad {
			log.Printf("【对话请求】【使用新API KEY: %s】【状态:正常】", km.displayKey(key))
			km.currentKey = key
			km.currentSession = ""
			km.lastUsedTime = now
			return key
		}

		if status.Bad && !status.BadTS.IsZero() {
			if now.Sub(status.BadTS) >= BadKeyRetryInterval {
				log.Printf("【KEY自动尝试恢复】API KEY: %s 满足重试周期,标记为正常", km.displayKey(key))
				status.Bad = false
				status.BadTS = time.Time{}
				km.currentKey = key
				km.currentSession = ""
				km.lastUsedTime = now
				return key
			}
		}
	}

	// 所有密钥都不可用,强制重置
	log.Printf("【警告】全部KEY已被禁用,强制选用第一个KEY继续尝试: %s", km.displayKey(km.keyList[0]))
	for _, key := range km.keyList {
		km.keyStatus[key].Bad = false
		km.keyStatus[key].BadTS = time.Time{}
	}
	km.idx = 0
	km.currentKey = km.keyList[0]
	km.currentSession = ""
	km.lastUsedTime = now
	log.Printf("【对话请求】【使用API KEY: %s】【状态:强制尝试（全部异常）】", km.displayKey(km.currentKey))
	return km.currentKey
}

// MarkBad 标记密钥为不可用
func (km *KeyManager) MarkBad(key string) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if status, exists := km.keyStatus[key]; exists && !status.Bad {
		log.Printf("【禁用KEY】API KEY: %s,接口返回无效（将在%d分钟后自动重试）",
			km.displayKey(key), int(BadKeyRetryInterval.Minutes()))
		status.Bad = true
		status.BadTS = time.Now()

		if km.currentKey == key {
			km.currentKey = ""
			km.currentSession = ""
		}
	}
}

// GetSession 获取或创建会话
func (km *KeyManager) GetSession(ctx context.Context, apikey string) (string, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	if km.currentSession == "" {
		session, err := createSession(ctx, apikey, "", nil)
		if err != nil {
			log.Printf("【创建会话失败】错误: %v", err)
			return "", err
		}
		km.currentSession = session
		log.Printf("【创建新会话】SESSION ID: %s", km.currentSession)
	}

	km.lastUsedTime = time.Now()
	return km.currentSession, nil
}

var keyManager *KeyManager

// HTTP请求结构
type ChatCompletionRequest struct {
	Messages []Message `json:"messages"`
	Model    string    `json:"model"`
	Stream   bool      `json:"stream"`
	Tools    []Tool    `json:"tools,omitempty"`
}

type Message struct {
	Role      string     `json:"role"`
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  ToolParameters `json:"parameters"`
}

type ToolParameters struct {
	Type       string                 `json:"type"`
	Properties map[string]PropertyDef `json:"properties"`
	Required   []string               `json:"required,omitempty"`
}

type PropertyDef struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

type ToolCall struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Function Function `json:"function"`
}

type Function struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// HTTP响应结构
type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

type Choice struct {
	Index        int      `json:"index"`
	Message      *Message `json:"message,omitempty"`
	Delta        *Message `json:"delta,omitempty"`
	FinishReason *string  `json:"finish_reason"`
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type ModelsResponse struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

// HTTP帮助函数
func getHTTPClient() *http.Client {
	return httpClientPool.Get().(*http.Client)
}

func putHTTPClient(client *http.Client) {
	httpClientPool.Put(client)
}

func getBuilder() *strings.Builder {
	b := builderPool.Get().(*strings.Builder)
	b.Reset()
	return b
}

func putBuilder(b *strings.Builder) {
	builderPool.Put(b)
}

func setCommonHeaders(req *http.Request, apikey string) {
	req.Header.Set("apikey", apikey)
	req.Header.Set("Content-Type", "application/json")
}

func generateChatCompletionID() string {
	return "chatcmpl-" + uuid.New().String()[:8]
}

func generateToolCallID() string {
	return fmt.Sprintf("call_%s", strings.ReplaceAll(uuid.New().String(), "-", "")[:16])
}

func createFunctionCallResponse(model string, parsedTool *FunctionCallResult, isStream bool) ChatCompletionResponse {
	toolCallID := generateToolCallID()
	argsJSON, _ := json.Marshal(parsedTool.Args)

	response := ChatCompletionResponse{
		ID:      generateChatCompletionID(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []Choice{{
			Index:        0,
			FinishReason: func() *string { s := "tool_calls"; return &s }(),
		}},
		Usage: Usage{},
	}

	if isStream {
		response.Object = "chat.completion.chunk"
		response.Choices[0].Delta = &Message{
			Role:    "assistant",
			Content: "",
			ToolCalls: []ToolCall{{
				ID:   toolCallID,
				Type: "function",
				Function: Function{
					Name:      parsedTool.Name,
					Arguments: string(argsJSON),
				},
			}},
		}
	} else {
		response.Choices[0].Message = &Message{
			Role:    "assistant",
			Content: "",
			ToolCalls: []ToolCall{{
				ID:   toolCallID,
				Type: "function",
				Function: Function{
					Name:      parsedTool.Name,
					Arguments: string(argsJSON),
				},
			}},
		}
	}

	return response
}

// OnDemand API 结构
type CreateSessionRequest struct {
	ExternalUserID string   `json:"externalUserId"`
	PluginIds      []string `json:"pluginIds,omitempty"`
}

type CreateSessionResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

type QueryRequest struct {
	Query        string   `json:"query"`
	EndpointID   string   `json:"endpointId"`
	PluginIds    []string `json:"pluginIds"`
	ResponseMode string   `json:"responseMode"`
}

type QueryResponse struct {
	Data struct {
		Answer string `json:"answer"`
	} `json:"data"`
}

// Function Calling 解析结果
type FunctionCallResult struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args"`
}

// generateFunctionPrompt 根据工具数组生成提示
func generateFunctionPrompt(tools []Tool) string {
	toolsList := getBuilder()
	defer putBuilder(toolsList)

	for i, tool := range tools {
		var params []string
		for name, prop := range tool.Function.Parameters.Properties {
			params = append(params, fmt.Sprintf("%s (%s)", name, prop.Type))
		}
		paramsStr := "无"
		if len(params) > 0 {
			paramsStr = strings.Join(params, ", ")
		}

		toolsList.WriteString(fmt.Sprintf("%d. <tool name=\"%s\" description=\"%s\">\n   参数：%s",
			i+1, tool.Function.Name, tool.Function.Description, paramsStr))

		if i < len(tools)-1 {
			toolsList.WriteString("\n\n")
		}
	}

	return strings.ReplaceAll(functionCallPromptTemplate, "{{TOOLS_LIST}}", toolsList.String())
}

// parseFunctionCallXML 解析模型输出的Function Call XML
func parseFunctionCallXML(xmlString string) *FunctionCallResult {
	// 提取 tool name
	toolRegex := regexp.MustCompile(`<tool>(.*?)</tool>`)
	toolMatch := toolRegex.FindStringSubmatch(xmlString)
	if len(toolMatch) < 2 {
		return nil
	}
	name := strings.TrimSpace(toolMatch[1])

	// 提取 args 块
	argsRegex := regexp.MustCompile(`<args>([\s\S]*?)</args>`)
	argsMatch := argsRegex.FindStringSubmatch(xmlString)

	args := make(map[string]string)
	if len(argsMatch) >= 2 {
		argsContent := argsMatch[1]
		// 单个参数的正则：<key>value</key>
		argRegex := regexp.MustCompile(`<(\w+)>(.*?)</(\w+)>`)
		argMatches := argRegex.FindAllStringSubmatch(argsContent, -1)

		for _, match := range argMatches {
			if len(match) >= 4 && match[1] == match[3] {
				args[match[1]] = match[2]
			}
		}
	}

	return &FunctionCallResult{
		Name: name,
		Args: args,
	}
}

// hasFunctionCallPrefix 检查响应是否以FC_USE开头
func hasFunctionCallPrefix(content string) bool {
	return strings.HasPrefix(strings.TrimSpace(content), "FC_USE")
}

// 初始化配置
func init() {
	// 加载 .env 文件
	err := godotenv.Load()
	if err != nil {
		log.Println("警告:没有找到 .env 文件,将仅使用系统环境变量")
	}
	initConfig()
}

func initConfig() {
	privateKey = getEnv("PRIVATE_KEY", "testofli")

	apiKeysStr := os.Getenv("ONDEMAND_APIKEYS")
	if apiKeysStr != "" {
		ondemandAPIKeys = strings.Split(apiKeysStr, ",")
	}

	if len(ondemandAPIKeys) == 0 && !isTestMode() {
		log.Fatal("ONDEMAND_APIKEYS 环境变量为空,请设置API密钥")
	}

	if len(ondemandAPIKeys) > 0 {
		keyManager = NewKeyManager(ondemandAPIKeys)
	}
}

func isTestMode() bool {
	for _, arg := range os.Args {
		if strings.Contains(arg, "test") {
			return true
		}
	}
	return os.Getenv("GIN_MODE") == "test"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// 权限检查中间件
func checkPrivateKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 放宽部分接口
		if c.Request.URL.Path == "/" || c.Request.URL.Path == "/favicon.ico" {
			c.Next()
			return
		}

		var key string
		for _, header := range safeHeaders {
			if value := c.GetHeader(header); value != "" {
				key = value
				if header == "Authorization" && strings.HasPrefix(value, "Bearer ") {
					key = strings.TrimSpace(value[7:])
				}
				break
			}
		}

		if key == "" || key != privateKey {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized, must provide correct Authorization or X-API-KEY",
				"headers": c.Request.Header,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// 获取端点ID
func getEndpointID(openaiModel string) string {
	model := strings.ToLower(strings.ReplaceAll(openaiModel, " ", ""))
	if endpoint, exists := modelMap[model]; exists {
		return endpoint
	}
	return ""
}

// 创建会话
func createSession(ctx context.Context, apikey, externalUserID string, pluginIds []string) (string, error) {
	if externalUserID == "" {
		externalUserID = uuid.New().String()
	}

	payload := CreateSessionRequest{
		ExternalUserID: externalUserID,
		PluginIds:      pluginIds,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", ondemandAPIBase+"/sessions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	setCommonHeaders(req, apikey)

	client := getHTTPClient()
	defer putHTTPClient(client)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create session failed with status: %d", resp.StatusCode)
	}

	var sessionResp CreateSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&sessionResp); err != nil {
		return "", err
	}

	return sessionResp.Data.ID, nil
}

// 执行带重试的操作
func withValidKey(ctx context.Context, fn func(ctx context.Context, key string) (interface{}, error)) (interface{}, error) {
	badCount := 0
	maxRetry := len(keyManager.keyList) * 2

	for badCount < maxRetry {
		key := keyManager.Get()
		result, err := fn(ctx, key)

		if err != nil {
			// 检查是否是需要标记密钥为坏的错误
			if isAuthError(err) {
				keyManager.MarkBad(key)
				badCount++
				continue
			}
			return nil, err
		}

		return result, nil
	}

	return nil, fmt.Errorf("没有可用API KEY,请补充新KEY或联系技术支持")
}

// 检查是否是认证相关错误
func isAuthError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "403") ||
		strings.Contains(errStr, "429") ||
		strings.Contains(errStr, "500")
}

// 聊天完成接口
func chatCompletions(c *gin.Context) {
	var req ChatCompletionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求缺少messages字段"})
		return
	}

	if len(req.Messages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求缺少messages字段"})
		return
	}

	// 处理function calling
	hasFunctionCall := len(req.Tools) > 0
	var functionPrompt string

	if hasFunctionCall {
		functionPrompt = generateFunctionPrompt(req.Tools)

		// 将系统提示添加到消息开头
		systemMessage := Message{
			Role:    "system",
			Content: functionPrompt,
		}
		req.Messages = append([]Message{systemMessage}, req.Messages...)
		log.Printf("【Function Calling】检测到%d个工具，已添加系统提示", len(req.Tools))
	}

	// 获取用户消息（构建合并消息用于上游API）
	userMsg := getBuilder()
	defer putBuilder(userMsg)
	for _, msg := range req.Messages {
		if msg.Role == "user" {
			if userMsg.Len() > 0 {
				userMsg.WriteString("\n\n")
			}
			userMsg.WriteString(msg.Content)
		} else if msg.Role == "system" {
			if userMsg.Len() > 0 {
				userMsg.WriteString("\n\n")
			}
			userMsg.WriteString(msg.Content)
		} else if msg.Role == "tool" {
			if userMsg.Len() > 0 {
				userMsg.WriteString("\n\n")
			}
			userMsg.WriteString(fmt.Sprintf("Tool result: %s", msg.Content))
		} else if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			// 处理assistant的工具调用消息
			if userMsg.Len() > 0 {
				userMsg.WriteString("\n\n")
			}
			for _, toolCall := range msg.ToolCalls {
				userMsg.WriteString(fmt.Sprintf("Called function: %s with arguments: %s",
					toolCall.Function.Name, toolCall.Function.Arguments))
			}
		}
	}

	if userMsg.Len() == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未找到用户消息"})
		return
	}

	endpointID := getEndpointID(req.Model)
	if endpointID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": map[string]interface{}{
				"message": fmt.Sprintf("The model '%s' does not exist", req.Model),
				"type":    "invalid_request_error",
				"param":   "model",
				"code":    "model_not_found",
			},
		})
		return
	}

	// 添加模型和端点的日志记录
	log.Printf("【模型请求】模型: %s, 端点: %s, 流式: %t, Function Calling: %t", req.Model, endpointID, req.Stream, hasFunctionCall)

	if req.Stream {
		handleStreamResponse(c, userMsg.String(), endpointID, req.Model, hasFunctionCall)
	} else {
		handleNonStreamResponse(c, userMsg.String(), endpointID, req.Model, hasFunctionCall)
	}
}

// 处理流式响应
func handleStreamResponse(c *gin.Context, userMsg, endpointID, model string, hasFunctionCall bool) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	// 使用channel进行异步处理
	resultChan := make(chan string, 100)
	errorChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errorChan)

		ctx := context.Background()
		result, err := withValidKey(ctx, func(ctx context.Context, apikey string) (interface{}, error) {
			return streamQuery(ctx, apikey, userMsg, endpointID, model, resultChan, hasFunctionCall)
		})

		if err != nil {
			errorChan <- err
			return
		}

		_ = result // 流式响应的结果通过channel传递
	}()

	// 处理响应流
	for {
		select {
		case chunk, ok := <-resultChan:
			if !ok {
				return
			}
			if chunk == "data: [DONE]" {
				_, _ = fmt.Fprintf(c.Writer, "data: [DONE]\n\n")
				c.Writer.Flush()
				return
			}
			_, _ = fmt.Fprintf(c.Writer, "data: %s\n\n", chunk)
			c.Writer.Flush()
		case err := <-errorChan:
			if err != nil {
				errorData := map[string]any{"error": err.Error()}
				errorJSON, _ := json.Marshal(errorData)
				_, _ = fmt.Fprintf(c.Writer, "data: %s\n\n", string(errorJSON))
				c.Writer.Flush()
			}
			return
		case <-c.Request.Context().Done():
			return
		}
	}
}

// 流式查询
func streamQuery(ctx context.Context, apikey, userMsg, endpointID, model string, resultChan chan<- string, hasFunctionCall bool) (interface{}, error) {
	sessionID, err := keyManager.GetSession(ctx, apikey)
	if err != nil {
		return nil, err
	}

	payload := QueryRequest{
		Query:        userMsg,
		EndpointID:   endpointID,
		PluginIds:    []string{},
		ResponseMode: "stream",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/sessions/%s/query", ondemandAPIBase, sessionID),
		bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	setCommonHeaders(req, apikey)
	req.Header.Set("Accept", "text/event-stream")

	client := getHTTPClient()
	defer putHTTPClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stream query failed with status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	firstChunk := true
	allContent := getBuilder() // 用于收集所有内容以检测function calling - 使用对象池
	defer putBuilder(allContent)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}

		dataPart := strings.TrimSpace(line[5:])
		if dataPart == "[DONE]" {
			// 在流结束时检查是否有function calling
			if hasFunctionCall && allContent.Len() > 0 {
				fullContent := allContent.String()
				if hasFunctionCallPrefix(fullContent) {
					parsedTool := parseFunctionCallXML(fullContent)
					if parsedTool != nil {
						funcCallChunk := createFunctionCallResponse(model, parsedTool, true)
						chunkJSON, _ := json.Marshal(funcCallChunk)
						resultChan <- string(chunkJSON)
					}
				}
			}
			resultChan <- "data: [DONE]"
			break
		}

		if strings.HasPrefix(dataPart, "[ERROR]:") {
			errJSON := strings.TrimSpace(dataPart[8:])
			resultChan <- fmt.Sprintf(`{"error": "%s"}`, errJSON)
			break
		}

		var eventData map[string]any
		if err := json.Unmarshal([]byte(dataPart), &eventData); err != nil {
			continue
		}

		// 处理不同类型的事件
		if eventType, ok := eventData["eventType"].(string); ok {
			var content string
			var hasContent bool

			switch eventType {
			case "fulfillment":
				if answer, ok := eventData["answer"].(string); ok {
					content = answer
					hasContent = true
				}
			case "stream", "thinking", "reasoning", "thoughts": // 可能的思考过程事件类型
				if answer, ok := eventData["answer"].(string); ok {
					content = answer
					hasContent = true
				} else if text, ok := eventData["text"].(string); ok {
					content = text
					hasContent = true
				} else if data, ok := eventData["data"].(string); ok {
					content = data
					hasContent = true
				} else if thoughts, ok := eventData["thoughts"].(string); ok {
					content = thoughts
					hasContent = true
				}
			default:
				// 对于未知事件类型,尝试提取任何文本内容
				if answer, ok := eventData["answer"].(string); ok {
					content = answer
					hasContent = true
				} else if text, ok := eventData["text"].(string); ok {
					content = text
					hasContent = true
				} else if thoughts, ok := eventData["thoughts"].(string); ok {
					content = thoughts
					hasContent = true
				}
			}

			if hasContent {
				// 收集所有内容用于function calling检测
				if hasFunctionCall {
					allContent.WriteString(content)
				}

				// 如果启用了function calling且检测到FC_USE，则不发送常规内容
				if hasFunctionCall && hasFunctionCallPrefix(allContent.String()) {
					continue
				}

				role := ""
				if firstChunk {
					role = "assistant"
				}

				chunk := ChatCompletionResponse{
					ID:      generateChatCompletionID(),
					Object:  "chat.completion.chunk",
					Created: time.Now().Unix(),
					Model:   model,
					Choices: []Choice{{
						Index: 0,
						Delta: &Message{
							Role:    role,
							Content: content,
						},
						FinishReason: nil,
					}},
				}

				chunkJSON, _ := json.Marshal(chunk)
				resultChan <- string(chunkJSON)
				firstChunk = false
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return nil, nil
}

// 处理非流式响应
func handleNonStreamResponse(c *gin.Context, userMsg, endpointID, model string, hasFunctionCall bool) {
	ctx := c.Request.Context()

	result, err := withValidKey(ctx, func(ctx context.Context, apikey string) (any, error) {
		return nonStreamQuery(ctx, apikey, userMsg, endpointID, model, hasFunctionCall)
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// 非流式查询
func nonStreamQuery(ctx context.Context, apikey, userMsg, endpointID, model string, hasFunctionCall bool) (any, error) {
	sessionID, err := keyManager.GetSession(ctx, apikey)
	if err != nil {
		return nil, err
	}

	payload := QueryRequest{
		Query:        userMsg,
		EndpointID:   endpointID,
		PluginIds:    []string{},
		ResponseMode: "sync",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/sessions/%s/query", ondemandAPIBase, sessionID),
		bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	setCommonHeaders(req, apikey)

	client := getHTTPClient()
	defer putHTTPClient(client)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-stream query failed with status: %d", resp.StatusCode)
	}

	var queryResp QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&queryResp); err != nil {
		return nil, err
	}

	content := queryResp.Data.Answer

	// 检查是否是function calling响应
	if hasFunctionCall && hasFunctionCallPrefix(content) {
		parsedTool := parseFunctionCallXML(content)
		if parsedTool != nil {
			response := createFunctionCallResponse(model, parsedTool, false)
			log.Printf("【Function Calling】解析到工具调用: %s, 参数: %v", parsedTool.Name, parsedTool.Args)
			return response, nil
		}
	}

	// 普通文本响应
	response := ChatCompletionResponse{
		ID:      generateChatCompletionID(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []Choice{{
			Index: 0,
			Message: &Message{
				Role:    "assistant",
				Content: content,
			},
			FinishReason: func() *string { s := "stop"; return &s }(),
		}},
		Usage: Usage{},
	}

	return response, nil
}

// 模型列表接口
func models(c *gin.Context) {
	var modelList []Model
	for modelID := range modelMap {
		modelList = append(modelList, Model{
			ID:      modelID,
			Object:  "model",
			OwnedBy: "ondemand-proxy",
		})
	}

	response := ModelsResponse{
		Object: "list",
		Data:   modelList,
	}

	c.JSON(http.StatusOK, response)
}

// 健康检查接口
func health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"keys":   len(ondemandAPIKeys),
	})
}

func main() {
	// 设置日志格式
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// 设置Gin模式
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// 中间件
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(checkPrivateKey())

	// 路由
	router.GET("/", health)
	router.POST("/v1/chat/completions", chatCompletions)
	router.GET("/v1/models", models)

	// 获取端口
	port := DefaultPort
	if portStr := os.Getenv("PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}

	log.Printf("======== OnDemand KEY池数量:%d ========", len(ondemandAPIKeys))
	log.Printf("服务器启动在端口:%d", port)

	// 启动服务器
	if err := router.Run(fmt.Sprintf(":%d", port)); err != nil {
		log.Fatal("启动服务器失败:", err)
	}
}
