package system

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"security-exporter/pkg/logger"
	"strings"
	"time"
)

// getProcessVersion 获取进程版本号
func getProcessVersion(processName string, exePath string, cmdLine string) string {
	logger.Debug("getProcessVersion: 开始获取进程名: %s, 路径: %s, 命令行: %s 的版本", processName, exePath, cmdLine)

	if processName == "" || processName == "unknown" {
		logger.Debug("getProcessVersion: 进程名为空或unknown，跳过")
		return ""
	}

	// 对于Java应用，需要特殊处理
	if isJavaProcess(processName) {
		logger.Debug("getProcessVersion: 检测到Java应用进程: %s", processName)

		// 方法1: 优先通过HTTP API获取（最快最准确）
		if version := getJavaAppVersionByHTTP(processName); version != "" {
			logger.Debug("getProcessVersion: Java应用通过HTTP API获取到版本: %s", version)
			return version
		}

		// 方法2: 从jar文件MANIFEST.MF获取（需要从命令行提取jar路径）
		if cmdLine != "" {
			if version := getJavaAppVersionFromCmdLine(cmdLine); version != "" {
				logger.Debug("getProcessVersion: Java应用从命令行jar文件获取到版本: %s", version)
				return version
			}
		}

		// 方法3: 从jar文件目录查找并读取MANIFEST.MF
		if version := getJavaAppVersionFromJar(processName); version != "" {
			logger.Debug("getProcessVersion: Java应用从jar目录获取到版本: %s", version)
			return version
		}

		// 方法4: 从配置文件或目录获取
		if version := getJavaAppVersionFromConfig(processName, exePath); version != "" {
			logger.Debug("getProcessVersion: Java应用从配置获取到版本: %s", version)
			return version
		}

		logger.Debug("getProcessVersion: Java应用 %s 所有方法都失败，无法获取版本", processName)
		return ""
	}

	// 非Java应用：方法1: 尝试执行版本命令
	logger.Debug("getProcessVersion: 非Java应用，尝试通过命令获取版本")
	if version := getVersionByCommand(processName, exePath); version != "" {
		logger.Debug("getProcessVersion: 通过命令获取到版本: %s", version)
		return version
	}

	// 非Java应用：方法2: 从可执行文件读取版本字符串
	if exePath != "" {
		logger.Debug("getProcessVersion: 尝试从二进制文件读取版本")
		if version := getVersionFromBinary(exePath); version != "" {
			logger.Debug("getProcessVersion: 从二进制文件获取到版本: %s", version)
			return version
		}
	}

	logger.Debug("getProcessVersion: 无法获取进程 %s 的版本", processName)
	return ""
}

// getVersionByCommand 通过执行命令获取版本
func getVersionByCommand(processName string, exePath string) string {
	// 定义常见的版本命令和模式
	versionCommands := map[string][]struct {
		cmd     string
		args    []string
		pattern string
	}{
		"mysql": {
			{cmd: "mysql", args: []string{"--version"}, pattern: `Ver\s+([\d.]+)`},
			{cmd: "mysqld", args: []string{"--version"}, pattern: `Ver\s+([\d.]+)`},
		},
		"mysqld": {
			{cmd: "mysqld", args: []string{"--version"}, pattern: `Ver\s+([\d.]+)`},
			{cmd: "mysql", args: []string{"--version"}, pattern: `Ver\s+([\d.]+)`},
		},
		"nginx": {
			{cmd: "nginx", args: []string{"-v"}, pattern: `nginx/([\d.]+)`},
		},
		"redis-server": {
			{cmd: "redis-server", args: []string{"--version"}, pattern: `v=([\d.]+)`},
			{cmd: "redis-cli", args: []string{"--version"}, pattern: `redis-cli\s+([\d.]+)`},
		},
		"postgres": {
			{cmd: "postgres", args: []string{"--version"}, pattern: `postgres.*?([\d.]+)`},
			{cmd: "psql", args: []string{"--version"}, pattern: `psql.*?([\d.]+)`},
		},
		"mongod": {
			{cmd: "mongod", args: []string{"--version"}, pattern: `version\s+v?([\d.]+)`},
		},
		"docker": {
			{cmd: "docker", args: []string{"--version"}, pattern: `version\s+([\d.]+)`},
			{cmd: "dockerd", args: []string{"--version"}, pattern: `version\s+([\d.]+)`},
		},
		"prometheus": {
			{cmd: "prometheus", args: []string{"--version"}, pattern: `prometheus.*?version\s+([\d.]+)`},
		},
		"apache2": {
			{cmd: "apache2", args: []string{"-v"}, pattern: `Server version: Apache/([\d.]+)`},
			{cmd: "httpd", args: []string{"-v"}, pattern: `Server version: Apache/([\d.]+)`},
		},
		"httpd": {
			{cmd: "httpd", args: []string{"-v"}, pattern: `Server version: Apache/([\d.]+)`},
		},
		"snmpd": {
			{cmd: "snmpd", args: []string{"-v"}, pattern: `version\s+([\d.]+)`},
		},
		// 移除Java应用的错误配置，它们将通过特殊方法处理
		"rabbitmq-server": {
			{cmd: "rabbitmqctl", args: []string{"version"}, pattern: `RabbitMQ\s+([\d.]+)`},
		},
		"minio": {
			{cmd: "minio", args: []string{"--version"}, pattern: `version\s+([\d.]+)`},
		},
		"mtail": {
			{cmd: "mtail", args: []string{"--version"}, pattern: `mtail version\s+([\d\w.-]+)`},
		},
		"tidb-server": {
			{cmd: "tidb-server", args: []string{"-V"}, pattern: `Release Version:\s+([\d.]+)`},
		},
		"victoria-metrics": {
			{cmd: "victoria-metrics-prod", args: []string{"--version"}, pattern: `victoria-metrics\s+([\d\w.-]+)`},
		},
	}

	// 先尝试直接使用进程名
	if commands, ok := versionCommands[processName]; ok {
		for _, cmd := range commands {
			if version := executeVersionCommand(cmd.cmd, cmd.args, cmd.pattern); version != "" {
				return version
			}
		}
	}

	// 如果可执行文件路径存在，尝试使用路径中的命令名
	if exePath != "" {
		cmdName := filepath.Base(exePath)
		if commands, ok := versionCommands[cmdName]; ok {
			for _, cmd := range commands {
				if version := executeVersionCommand(cmd.cmd, cmd.args, cmd.pattern); version != "" {
					return version
				}
			}
		}
		// 尝试直接用可执行文件路径执行版本命令
		if version := executeVersionCommand(exePath, []string{"--version"}, `version\s+([\d.]+)`); version != "" {
			return version
		}
		if version := executeVersionCommand(exePath, []string{"-v"}, `([\d.]+)`); version != "" {
			return version
		}
		if version := executeVersionCommand(exePath, []string{"-V"}, `([\d.]+)`); version != "" {
			return version
		}
	}

	return ""
}

// executeVersionCommand 执行版本命令并解析结果
func executeVersionCommand(cmd string, args []string, pattern string) string {
	logger.Debug("executeVersionCommand: 执行命令 %s %v", cmd, args)

	// 检查命令是否存在
	if _, err := exec.LookPath(cmd); err != nil {
		logger.Debug("executeVersionCommand: 命令 %s 不存在", cmd)
		return ""
	}

	fullCmd := exec.Command(cmd, args...)
	output, err := fullCmd.CombinedOutput()
	if err != nil {
		logger.Debug("executeVersionCommand: 命令执行失败: %v", err)
		return ""
	}

	re := regexp.MustCompile("(?i)" + pattern)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		version := strings.TrimSpace(matches[1])
		logger.Debug("executeVersionCommand: 解析到版本: %s", version)
		return version
	}

	return ""
}

// getVersionFromBinary 从二进制文件读取版本信息
func getVersionFromBinary(exePath string) string {
	if exePath == "" {
		return ""
	}

	logger.Debug("getVersionFromBinary: 从文件 %s 读取版本信息", exePath)

	// 读取二进制文件的一部分（前1MB通常包含版本字符串）
	content, err := os.ReadFile(exePath)
	if err != nil {
		logger.Debug("getVersionFromBinary: 无法读取文件: %v", err)
		return ""
	}

	// 限制读取大小，避免读取过大文件
	maxSize := 1024 * 1024 // 1MB
	if len(content) > maxSize {
		content = content[:maxSize]
	}

	contentStr := string(content)

	// 常见的版本字符串模式
	patterns := []string{
		`version\s+([\d.]+)`,
		`v([\d.]+)`,
		`([\d]+\.[\d]+\.[\d]+)`,
		`([\d]+\.[\d]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile("(?i)" + pattern)
		matches := re.FindAllStringSubmatch(contentStr, -1)
		// 取最后一个匹配，通常是主版本号
		if len(matches) > 0 {
			for i := len(matches) - 1; i >= 0; i-- {
				if len(matches[i]) > 1 {
					version := strings.TrimSpace(matches[i][1])
					// 验证是否为合理的版本号格式
					if regexp.MustCompile(`^\d+\.\d+`).MatchString(version) {
						logger.Debug("getVersionFromBinary: 从文件解析到版本: %s", version)
						return version
					}
				}
			}
		}
	}

	logger.Debug("getVersionFromBinary: 无法从文件解析到版本")
	return ""
}

// isJavaProcess 判断是否为Java进程
func isJavaProcess(processName string) bool {
	logger.Debug("isJavaProcess: 检查进程名 %s 是否为Java进程", processName)

	javaProcessNames := []string{
		"java", "elasticsearch", "kafka", "logstash", "tomcat",
		"jenkins", "zookeeper", "solr", "cassandra", "hadoop",
	}

	nameLower := strings.ToLower(processName)
	for _, javaProc := range javaProcessNames {
		if strings.Contains(nameLower, javaProc) {
			logger.Debug("isJavaProcess: 进程 %s 匹配Java进程关键词: %s", processName, javaProc)
			return true
		}
	}

	logger.Debug("isJavaProcess: 进程 %s 不是Java进程", processName)
	return false
}

// getJavaAppVersionByHTTP 通过HTTP API获取Java应用版本
func getJavaAppVersionByHTTP(processName string) string {
	logger.Debug("getJavaAppVersionByHTTP: 开始通过HTTP API获取进程 %s 的版本", processName)

	// 定义应用的HTTP API端点
	httpEndpoints := map[string]struct {
		url     string
		path    string // JSON路径，如 "version.number" 或 "number"
		pattern string // 正则表达式模式（备用）
	}{
		"elasticsearch": {
			url:  "http://localhost:9200",
			path: "version.number",
		},
		"logstash": {
			url:  "http://localhost:9600/_node/stats",
			path: "version", // Logstash可能返回版本信息
		},
		"tomcat": {
			url:     "http://localhost:8080/",
			pattern: `Apache Tomcat/([\d.]+)`,
		},
		"jenkins": {
			url:     "http://localhost:8080/login",
			pattern: `Jenkins ver\.\s+([\d.]+)`,
		},
	}

	processNameLower := strings.ToLower(processName)
	var endpoint *struct {
		url     string
		path    string
		pattern string
	}

	for key, ep := range httpEndpoints {
		if strings.Contains(processNameLower, key) {
			endpoint = &ep
			logger.Debug("getJavaAppVersionByHTTP: 找到匹配的HTTP端点: %s -> %s", key, ep.url)
			break
		}
	}

	if endpoint == nil {
		logger.Debug("getJavaAppVersionByHTTP: 未找到进程 %s 的HTTP端点配置", processName)
		return ""
	}

	logger.Debug("getJavaAppVersionByHTTP: 尝试访问 %s", endpoint.url)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(endpoint.url)
	if err != nil {
		logger.Debug("getJavaAppVersionByHTTP: HTTP请求失败: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Debug("getJavaAppVersionByHTTP: HTTP响应状态码: %d", resp.StatusCode)
		return ""
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Debug("getJavaAppVersionByHTTP: 读取响应失败: %v", err)
		return ""
	}

	logger.Debug("getJavaAppVersionByHTTP: 收到响应，长度: %d 字节", len(body))

	// 如果有JSON路径，解析JSON
	if endpoint.path != "" {
		logger.Debug("getJavaAppVersionByHTTP: 尝试从JSON路径 %s 解析版本", endpoint.path)
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err == nil {
			keys := strings.Split(endpoint.path, ".")
			var value interface{} = data
			for i, key := range keys {
				if m, ok := value.(map[string]interface{}); ok {
					if v, exists := m[key]; exists {
						value = v
						logger.Debug("getJavaAppVersionByHTTP: JSON路径 %s 找到值: %v", strings.Join(keys[:i+1], "."), v)
					} else {
						logger.Debug("getJavaAppVersionByHTTP: JSON路径 %s 不存在", strings.Join(keys[:i+1], "."))
						return ""
					}
				} else {
					logger.Debug("getJavaAppVersionByHTTP: JSON路径 %s 不是对象", strings.Join(keys[:i], "."))
					return ""
				}
			}
			if str, ok := value.(string); ok {
				logger.Debug("getJavaAppVersionByHTTP: 从JSON路径获取到版本: %s", str)
				return str
			}
			version := fmt.Sprintf("%v", value)
			logger.Debug("getJavaAppVersionByHTTP: 从JSON路径获取到版本: %s", version)
			return version
		} else {
			logger.Debug("getJavaAppVersionByHTTP: JSON解析失败: %v", err)
		}
	}

	// 如果有正则模式，使用正则匹配
	if endpoint.pattern != "" {
		logger.Debug("getJavaAppVersionByHTTP: 尝试使用正则模式 %s 匹配", endpoint.pattern)
		re := regexp.MustCompile("(?i)" + endpoint.pattern)
		matches := re.FindStringSubmatch(string(body))
		if len(matches) > 1 {
			version := strings.TrimSpace(matches[1])
			logger.Debug("getJavaAppVersionByHTTP: 使用正则模式获取到版本: %s", version)
			return version
		}
		logger.Debug("getJavaAppVersionByHTTP: 正则模式未匹配到版本")
	}

	logger.Debug("getJavaAppVersionByHTTP: 无法从HTTP API获取版本")
	return ""
}

// getJavaAppVersionFromCmdLine 从命令行提取jar文件路径并获取版本
func getJavaAppVersionFromCmdLine(cmdLine string) string {
	logger.Debug("getJavaAppVersionFromCmdLine: 从命令行提取jar文件: %s", cmdLine)

	// 从命令行中提取jar文件路径
	jarPattern := regexp.MustCompile(`([/\w\-\.]+[/\\][\w\-\.]+\.jar)`)
	matches := jarPattern.FindAllStringSubmatch(cmdLine, -1)

	if len(matches) == 0 {
		logger.Debug("getJavaAppVersionFromCmdLine: 命令行中未找到jar文件")
		return ""
	}

	logger.Debug("getJavaAppVersionFromCmdLine: 找到 %d 个jar文件路径", len(matches))

	// 尝试每个jar文件，找到主jar（通常包含应用名称）
	for _, match := range matches {
		jarPath := match[1]
		logger.Debug("getJavaAppVersionFromCmdLine: 尝试jar文件: %s", jarPath)

		// 检查文件是否存在
		if _, err := os.Stat(jarPath); err != nil {
			logger.Debug("getJavaAppVersionFromCmdLine: jar文件不存在: %s, 错误: %v", jarPath, err)
			continue
		}

		// 从jar文件的MANIFEST.MF获取版本
		if version := getVersionFromJarManifest(jarPath); version != "" {
			logger.Debug("getJavaAppVersionFromCmdLine: 从jar文件 %s 获取到版本: %s", jarPath, version)
			return version
		}
	}

	logger.Debug("getJavaAppVersionFromCmdLine: 无法从命令行jar文件获取版本")
	return ""
}

// getVersionFromJarManifest 从jar文件的MANIFEST.MF读取版本
func getVersionFromJarManifest(jarPath string) string {
	logger.Debug("getVersionFromJarManifest: 从jar文件 %s 读取MANIFEST.MF", jarPath)

	jarFile, err := zip.OpenReader(jarPath)
	if err != nil {
		logger.Debug("getVersionFromJarManifest: 无法打开jar文件: %v", err)
		return ""
	}
	defer jarFile.Close()

	logger.Debug("getVersionFromJarManifest: jar文件打开成功，查找MANIFEST.MF")

	// 查找MANIFEST.MF文件
	var manifestFile *zip.File
	for _, file := range jarFile.File {
		if file.Name == "META-INF/MANIFEST.MF" || file.Name == "MANIFEST.MF" {
			manifestFile = file
			logger.Debug("getVersionFromJarManifest: 找到MANIFEST.MF: %s", file.Name)
			break
		}
	}

	if manifestFile == nil {
		logger.Debug("getVersionFromJarManifest: 未找到MANIFEST.MF文件")
		return ""
	}

	rc, err := manifestFile.Open()
	if err != nil {
		logger.Debug("getVersionFromJarManifest: 无法打开MANIFEST.MF: %v", err)
		return ""
	}
	defer rc.Close()

	content, err := ioutil.ReadAll(rc)
	if err != nil {
		logger.Debug("getVersionFromJarManifest: 读取MANIFEST.MF失败: %v", err)
		return ""
	}

	manifestStr := string(content)
	logger.Debug("getVersionFromJarManifest: MANIFEST.MF内容长度: %d 字节", len(manifestStr))

	// 查找版本信息
	versionPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"Elasticsearch-Version", regexp.MustCompile(`(?i)Elasticsearch-Version:\s*([\d.]+)`)},
		{"Kafka-Version", regexp.MustCompile(`(?i)Kafka-Version:\s*([\d.]+)`)},
		{"Implementation-Version", regexp.MustCompile(`(?i)Implementation-Version:\s*([\d.]+)`)},
		{"Bundle-Version", regexp.MustCompile(`(?i)Bundle-Version:\s*([\d.]+)`)},
		{"Version", regexp.MustCompile(`(?i)Version:\s*([\d.]+)`)},
	}

	for _, vp := range versionPatterns {
		matches := vp.pattern.FindStringSubmatch(manifestStr)
		if len(matches) > 1 {
			version := strings.TrimSpace(matches[1])
			logger.Debug("getVersionFromJarManifest: 使用模式 %s 解析到版本: %s", vp.name, version)
			return version
		}
	}

	logger.Debug("getVersionFromJarManifest: MANIFEST.MF中未找到版本信息")

	// 从jar文件名提取版本（备用方案）
	baseName := filepath.Base(jarPath)
	logger.Debug("getVersionFromJarManifest: 尝试从文件名提取版本: %s", baseName)
	re := regexp.MustCompile(`-([\d]+\.[\d]+(?:\.[\d]+)?)\.jar$`)
	matches := re.FindStringSubmatch(baseName)
	if len(matches) > 1 {
		version := strings.TrimSpace(matches[1])
		logger.Debug("getVersionFromJarManifest: 从文件名解析到版本: %s", version)
		return version
	}

	logger.Debug("getVersionFromJarManifest: 无法从jar文件获取版本")
	return ""
}

// getJavaAppVersionFromJar 从jar文件目录查找并读取MANIFEST.MF
func getJavaAppVersionFromJar(processName string) string {
	logger.Debug("getJavaAppVersionFromJar: 从jar目录查找进程 %s 的版本", processName)

	processNameLower := strings.ToLower(processName)

	// 定义常见的jar文件路径模式
	jarPatterns := []struct {
		name  string
		paths []string
		regex *regexp.Regexp
	}{
		{
			name: "elasticsearch",
			paths: []string{
				"/usr/share/elasticsearch/lib",
				"/opt/elasticsearch/lib",
				"/var/lib/elasticsearch/lib",
			},
			regex: regexp.MustCompile(`elasticsearch-([\d.]+)\.jar`),
		},
		{
			name: "kafka",
			paths: []string{
				"/opt/kafka/libs",
				"/usr/share/kafka/libs",
			},
			regex: regexp.MustCompile(`kafka_[\d.]+-([\d.]+)\.jar`),
		},
		{
			name: "logstash",
			paths: []string{
				"/opt/logstash/logstash-core/lib/logstash-core",
				"/usr/share/logstash/logstash-core/lib/logstash-core",
			},
			regex: regexp.MustCompile(`logstash-core-([\d.]+)\.jar`),
		},
		{
			name: "tomcat",
			paths: []string{
				"/usr/share/tomcat/lib",
				"/opt/tomcat/lib",
			},
			regex: regexp.MustCompile(`catalina\.jar`), // Tomcat版本在MANIFEST.MF中
		},
	}

	// 查找匹配的应用
	for _, app := range jarPatterns {
		if strings.Contains(processNameLower, app.name) {
			logger.Debug("getJavaAppVersionFromJar: 匹配到应用: %s", app.name)
			for _, libPath := range app.paths {
				logger.Debug("getJavaAppVersionFromJar: 检查路径: %s", libPath)
				if entries, err := os.ReadDir(libPath); err == nil {
					logger.Debug("getJavaAppVersionFromJar: 路径存在，找到 %d 个文件", len(entries))
					for _, entry := range entries {
						fileName := entry.Name()
						logger.Debug("getJavaAppVersionFromJar: 检查文件: %s", fileName)

						// 尝试从文件名提取版本
						matches := app.regex.FindStringSubmatch(fileName)
						if len(matches) > 1 {
							version := matches[1]
							logger.Debug("getJavaAppVersionFromJar: 从文件名提取到版本: %s", version)
							return version
						}

						// 或者读取MANIFEST.MF
						if strings.HasSuffix(fileName, ".jar") {
							jarPath := filepath.Join(libPath, fileName)
							if version := getVersionFromJarManifest(jarPath); version != "" {
								logger.Debug("getJavaAppVersionFromJar: 从jar文件 %s 获取到版本: %s", jarPath, version)
								return version
							}
						}
					}
				} else {
					logger.Debug("getJavaAppVersionFromJar: 路径不存在: %s, 错误: %v", libPath, err)
				}
			}
		}
	}

	logger.Debug("getJavaAppVersionFromJar: 无法从jar目录获取版本")
	return ""
}

// getJavaAppVersionFromConfig 从配置文件或目录获取版本
func getJavaAppVersionFromConfig(processName string, exePath string) string {
	logger.Debug("getJavaAppVersionFromConfig: 从配置获取进程 %s 的版本", processName)

	processNameLower := strings.ToLower(processName)

	// Elasticsearch: 从lib目录的jar文件名获取
	if strings.Contains(processNameLower, "elasticsearch") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Elasticsearch配置方法")
		esLibPaths := []string{
			"/usr/share/elasticsearch/lib",
			"/opt/elasticsearch/lib",
			"/var/lib/elasticsearch/lib",
		}
		for _, libPath := range esLibPaths {
			logger.Debug("getJavaAppVersionFromConfig: 检查Elasticsearch路径: %s", libPath)
			if entries, err := os.ReadDir(libPath); err == nil {
				logger.Debug("getJavaAppVersionFromConfig: 路径存在，找到 %d 个文件", len(entries))
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "elasticsearch-") && strings.HasSuffix(entry.Name(), ".jar") {
						re := regexp.MustCompile(`elasticsearch-([\d.]+)\.jar`)
						matches := re.FindStringSubmatch(entry.Name())
						if len(matches) > 1 {
							version := matches[1]
							logger.Debug("getJavaAppVersionFromConfig: 从Elasticsearch jar文件名获取到版本: %s", version)
							return version
						}
					}
				}
			}
		}
	}

	// Kafka: 从libs目录的jar文件名获取
	if strings.Contains(processNameLower, "kafka") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Kafka配置方法")
		kafkaPaths := []string{
			"/opt/kafka",
			"/usr/share/kafka",
		}
		for _, kafkaPath := range kafkaPaths {
			libPath := filepath.Join(kafkaPath, "libs")
			logger.Debug("getJavaAppVersionFromConfig: 检查Kafka路径: %s", libPath)
			if entries, err := os.ReadDir(libPath); err == nil {
				logger.Debug("getJavaAppVersionFromConfig: 路径存在，找到 %d 个文件", len(entries))
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "kafka_") && strings.HasSuffix(entry.Name(), ".jar") {
						// Kafka版本格式: kafka_2.13-3.5.0.jar，提取3.5.0
						re := regexp.MustCompile(`kafka_[\d.]+-([\d.]+)\.jar`)
						matches := re.FindStringSubmatch(entry.Name())
						if len(matches) > 1 {
							version := matches[1]
							logger.Debug("getJavaAppVersionFromConfig: 从Kafka jar文件名获取到版本: %s", version)
							return version
						}
					}
				}
			}
		}
	}

	// Logstash: 从logstash-core jar文件名获取
	if strings.Contains(processNameLower, "logstash") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Logstash配置方法")
		logstashPaths := []string{
			"/opt/logstash",
			"/usr/share/logstash",
		}
		for _, logstashPath := range logstashPaths {
			coreLibPath := filepath.Join(logstashPath, "logstash-core", "lib", "logstash-core")
			logger.Debug("getJavaAppVersionFromConfig: 检查Logstash路径: %s", coreLibPath)
			if entries, err := os.ReadDir(coreLibPath); err == nil {
				logger.Debug("getJavaAppVersionFromConfig: 路径存在，找到 %d 个文件", len(entries))
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "logstash-core-") && strings.HasSuffix(entry.Name(), ".jar") {
						re := regexp.MustCompile(`logstash-core-([\d.]+)\.jar`)
						matches := re.FindStringSubmatch(entry.Name())
						if len(matches) > 1 {
							version := matches[1]
							logger.Debug("getJavaAppVersionFromConfig: 从Logstash jar文件名获取到版本: %s", version)
							return version
						}
					}
				}
			}
		}
	}

	logger.Debug("getJavaAppVersionFromConfig: 无法从配置获取版本")
	return ""
}
