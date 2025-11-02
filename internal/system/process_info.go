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
// function isJavaProcess(processName string) bool
func isJavaProcess(processName string) bool {
	logger.Debug("isJavaProcess: 检查进程名 %s 是否为Java进程", processName)

	javaProcessNames := []string{
		"java", "javaw", "elasticsearch", "kafka", "logstash", "tomcat",
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
	logger.Debug("getJavaAppVersionFromCmdLine: 从命令行提取jar/war文件: %s", cmdLine)

	// Linux-only：支持引号中的路径、绝对路径、相对文件名
	jarPattern := regexp.MustCompile(`(?i)"([^"]+\.(?:jar|war))"|(/[^\s"]+\.(?:jar|war))|(\b[\w\-.]+\.jar\b|\b[\w\-.]+\.war\b)`)
	matches := jarPattern.FindAllStringSubmatch(cmdLine, -1)

	extractPath := func(subs []string) string {
		for i := 1; i < len(subs); i++ {
			p := strings.TrimSpace(subs[i])
			if p != "" {
				return strings.Trim(p, `"`)
			}
		}
		return ""
	}

	if len(matches) > 0 {
		logger.Debug("getJavaAppVersionFromCmdLine: 找到 %d 个jar/war文件", len(matches))
		var jarPaths []string
		for _, m := range matches {
			jarPath := extractPath(m)
			if jarPath == "" {
				continue
			}
			if _, err := os.Stat(jarPath); err != nil {
				logger.Debug("getJavaAppVersionFromCmdLine: 文件不存在: %s, 错误: %v", jarPath, err)
				continue
			}
			jarPaths = append(jarPaths, jarPath)
		}
		// 优先匹配主程序 jar 名称（集中维护）
		mainJarRegexes := getAllMainJarRegexes()
		for _, jp := range jarPaths {
			base := filepath.Base(jp)
			for _, re := range mainJarRegexes {
				if re.MatchString(base) {
					if m := re.FindStringSubmatch(base); len(m) > 1 {
						version := strings.TrimSpace(m[1])
						logger.Debug("getJavaAppVersionFromCmdLine: 主程序文件名提取到版本: %s", version)
						return version
					}
					if version := getVersionFromJarManifest(jp); version != "" {
						logger.Debug("getJavaAppVersionFromCmdLine: 主程序 MANIFEST 提取到版本: %s", version)
						return version
					}
				}
			}
		}
		// 兜底：遍历所有 jar/war 的 MANIFEST（可能是依赖库）
		for _, jp := range jarPaths {
			if version := getVersionFromJarManifest(jp); version != "" {
				logger.Debug("getJavaAppVersionFromCmdLine: 兜底从 %s 获取到版本: %s", jp, version)
				return version
			}
		}
	} else {
		logger.Debug("getJavaAppVersionFromCmdLine: 命令行中未直接找到jar/war文件")
	}

	// 解析 -cp/-classpath，提取 classpath 项并尝试主程序 jar 优先匹配
	cpEntries := extractClasspathEntries(cmdLine)
	if len(cpEntries) > 0 {
		logger.Debug("getJavaAppVersionFromCmdLine: 解析到 %d 个 classpath 项", len(cpEntries))
		mainJarRegexes := getAllMainJarRegexes()
		for _, entry := range cpEntries {
			e := strings.TrimSpace(entry)
			if e == "" {
				continue
			}
			// 展开 lib/*
			if strings.HasSuffix(e, "/*") {
				dir := strings.TrimSuffix(e, "/*")
				if version := findVersionInLibDirWithPriority(dir, mainJarRegexes, nil); version != "" {
					logger.Debug("getJavaAppVersionFromCmdLine: 从 classpath 目录 %s 获取到版本: %s", dir, version)
					return version
				}
				continue
			}
			// 目录：尝试扫描
			if fi, err := os.Stat(e); err == nil && fi.IsDir() {
				if version := findVersionInLibDirWithPriority(e, mainJarRegexes, nil); version != "" {
					logger.Debug("getJavaAppVersionFromCmdLine: 从 classpath 目录 %s 获取到版本: %s", e, version)
					return version
				}
				continue
			}
			// 文件：jar/war 处理
			ext := strings.ToLower(filepath.Ext(e))
			if ext == ".jar" || ext == ".war" {
				base := filepath.Base(e)
				for _, re := range mainJarRegexes {
					if re.MatchString(base) {
						if m := re.FindStringSubmatch(base); len(m) > 1 {
							version := strings.TrimSpace(m[1])
							logger.Debug("getJavaAppVersionFromCmdLine: 主程序文件名提取到版本: %s", version)
							return version
						}
						if version := getVersionFromJarManifest(e); version != "" {
							logger.Debug("getJavaAppVersionFromCmdLine: 主程序 MANIFEST 提取到版本: %s", version)
							return version
						}
					}
				}
				// 兜底：如果 classpath 指明的是某个 jar，则尝试 MANIFEST
				if version := getVersionFromJarManifest(e); version != "" {
					logger.Debug("getJavaAppVersionFromCmdLine: 兜底从 %s 获取到版本: %s", e, version)
					return version
				}
			}
		}
	}

	// 解析 -Dxxx=yyy JVM 属性定位安装目录
	props := extractJavaPropsFromCmdLine(cmdLine)
	if len(props) > 0 {
		logger.Debug("getJavaAppVersionFromCmdLine: 解析到 %d 个 JVM 属性", len(props))
		// Elasticsearch
		if home := firstNonEmpty(props["es.path.home"], props["path.home"]); home != "" {
			if version := findVersionInLibDirWithPriority(filepath.Join(home, "lib"), []*regexp.Regexp{getMainJarRegex("elasticsearch")}, nil); version != "" {
				return version
			}
		}
		// Logstash
		if home := props["logstash.home"]; home != "" {
			coreLib := filepath.Join(home, "logstash-core", "lib", "logstash-core")
			if version := findVersionInLibDirWithPriority(coreLib, []*regexp.Regexp{getMainJarRegex("logstash")}, nil); version != "" {
				return version
			}
		}
		// Kafka
		if home := firstNonEmpty(props["kafka.home"], props["kafka.base"]); home != "" {
			if version := findVersionInLibDirWithPriority(filepath.Join(home, "libs"), []*regexp.Regexp{getMainJarRegex("kafka")}, nil); version != "" {
				return version
			}
		}
		// Tomcat
		if home := firstNonEmpty(props["catalina.base"], props["catalina.home"]); home != "" {
			if version := findVersionInLibDirWithPriority(filepath.Join(home, "lib"), []*regexp.Regexp{getMainJarRegex("tomcat")}, nil); version != "" {
				return version
			}
		}
		// Jenkins
		if home := firstNonEmpty(props["jenkins.home"], props["JENKINS_HOME"]); home != "" {
			if version := findVersionInLibDirWithPriority(home, []*regexp.Regexp{getMainJarRegex("jenkins")}, nil); version != "" {
				return version
			}
		}
		// Zookeeper
		if home := props["zookeeper.home"]; home != "" {
			if version := findVersionInLibDirWithPriority(filepath.Join(home, "lib"), []*regexp.Regexp{getMainJarRegex("zookeeper")}, nil); version != "" {
				return version
			}
		}
		// Cassandra
		if home := firstNonEmpty(props["cassandra.home"], props["cassandra.base"]); home != "" {
			if version := findVersionInLibDirWithPriority(filepath.Join(home, "lib"), []*regexp.Regexp{getMainJarRegex("cassandra")}, nil); version != "" {
				return version
			}
		}
		// Solr
		if home := firstNonEmpty(props["solr.install.dir"], props["solr.home"]); home != "" {
			if version := findVersionInLibDirWithPriority(filepath.Join(home, "server", "lib"), []*regexp.Regexp{getMainJarRegex("solr")}, nil); version != "" {
				return version
			}
			if version := findVersionInLibDirWithPriority(filepath.Join(home, "server", "solr", "lib"), []*regexp.Regexp{getMainJarRegex("solr")}, nil); version != "" {
				return version
			}
		}
	}

	logger.Debug("getJavaAppVersionFromCmdLine: 无法从命令行/属性获取版本")
	return ""
}

// getVersionFromJarManifest 从jar文件的MANIFEST.MF读取版本
// function getVersionFromJarManifest(jarPath string) string
func getVersionFromJarManifest(jarPath string) string {
	logger.Debug("getVersionFromJarManifest: 从压缩文件 %s 读取MANIFEST.MF", jarPath)

	jarFile, err := zip.OpenReader(jarPath)
	if err != nil {
		logger.Debug("getVersionFromJarManifest: 无法打开文件: %v", err)
		return ""
	}
	defer jarFile.Close()

	// 定位 MANIFEST.MF
	var manifestFile *zip.File
	for _, file := range jarFile.File {
		if file.Name == "META-INF/MANIFEST.MF" || file.Name == "MANIFEST.MF" {
			manifestFile = file
			break
		}
	}
	if manifestFile == nil {
		logger.Debug("getVersionFromJarManifest: 未找到MANIFEST.MF")
		// 作为兜底尝试从文件名提取
		baseName := filepath.Base(jarPath)
		re := regexp.MustCompile(`-([\d]+\.[\d]+(?:\.[\d]+)?)\.(?:jar|war)$`)
		if m := re.FindStringSubmatch(baseName); len(m) > 1 {
			version := strings.TrimSpace(m[1])
			logger.Debug("getVersionFromJarManifest: 兜底从文件名解析到版本: %s", version)
			return version
		}
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

	// 常见的版本字段（覆盖更多情况）
	versionPatterns := []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"Elasticsearch-Version", regexp.MustCompile(`(?i)^Elasticsearch-Version:\s*([\d.]+)\s*$`)},
		{"Kafka-Version", regexp.MustCompile(`(?i)^Kafka-Version:\s*([\d.]+)\s*$`)},
		{"Implementation-Version", regexp.MustCompile(`(?i)^Implementation-Version:\s*([\d\w\.\-]+)\s*$`)},
		{"Bundle-Version", regexp.MustCompile(`(?i)^Bundle-Version:\s*([\d\w\.\-]+)\s*$`)},
		{"Specification-Version", regexp.MustCompile(`(?i)^Specification-Version:\s*([\d\w\.\-]+)\s*$`)},
		{"Version", regexp.MustCompile(`(?i)^Version:\s*([\d\w\.\-]+)\s*$`)},
	}

	for _, vp := range versionPatterns {
		if m := vp.pattern.FindStringSubmatch(manifestStr); len(m) > 1 {
			version := strings.TrimSpace(m[1])
			// 过滤掉明显不合理的值
			if regexp.MustCompile(`^\d+\.\d+`).MatchString(version) || regexp.MustCompile(`^\d[\d\w\.\-]+$`).MatchString(version) {
				logger.Debug("getVersionFromJarManifest: 使用模式 %s 解析到版本: %s", vp.name, version)
				return version
			}
		}
	}

	// 兜底：从文件名解析（允许 -SNAPSHOT 等后缀）
	baseName := filepath.Base(jarPath)
	re := regexp.MustCompile(`-([\d][\d\w\.-]+)\.(?:jar|war)$`)
	if m := re.FindStringSubmatch(baseName); len(m) > 1 {
		version := strings.TrimSpace(m[1])
		logger.Debug("getVersionFromJarManifest: 兜底从文件名解析到版本: %s", version)
		return version
	}

	logger.Debug("getVersionFromJarManifest: MANIFEST.MF中未找到版本信息")
	return ""
}

// getJavaAppVersionFromJar 从jar文件目录查找并读取MANIFEST.MF
func getJavaAppVersionFromJar(processName string) string {
	logger.Debug("getJavaAppVersionFromJar: 从jar/war目录查找进程 %s 的版本", processName)

	processNameLower := strings.ToLower(processName)

	// 常见应用的库目录（Linux-only）
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
			regex: getMainJarRegex("elasticsearch"),
		},
		{
			name: "kafka",
			paths: []string{
				"/opt/kafka/libs",
				"/usr/share/kafka/libs",
			},
			regex: getMainJarRegex("kafka"),
		},
		{
			name: "logstash",
			paths: []string{
				"/opt/logstash/logstash-core/lib/logstash-core",
				"/usr/share/logstash/logstash-core/lib/logstash-core",
			},
			regex: getMainJarRegex("logstash"),
		},
		{
			name: "tomcat",
			paths: []string{
				"/usr/share/tomcat/lib",
				"/opt/tomcat/lib",
			},
			regex: getMainJarRegex("tomcat"),
		},
		{
			name: "jenkins",
			paths: []string{
				"/usr/share/jenkins",
				"/opt/jenkins",
				"/var/lib/jenkins",
			},
			regex: getMainJarRegex("jenkins"),
		},
		{
			name: "zookeeper",
			paths: []string{
				"/usr/share/zookeeper/lib",
				"/opt/zookeeper/lib",
			},
			regex: getMainJarRegex("zookeeper"),
		},
		{
			name: "cassandra",
			paths: []string{
				"/usr/share/cassandra/lib",
				"/opt/cassandra/lib",
			},
			regex: getMainJarRegex("cassandra"),
		},
		{
			name: "solr",
			paths: []string{
				"/opt/solr/server/lib",
				"/usr/share/solr/server/lib",
			},
			regex: getMainJarRegex("solr"),
		},
		{
			name: "nexus",
			paths: []string{
				"/opt/sonatype/nexus/lib",
				"/usr/share/sonatype/nexus/lib",
				"/usr/share/nexus/lib",
				"/opt/nexus/lib",
			},
			regex: getMainJarRegex("nexus"),
		},
		{
			name: "activemq",
			paths: []string{
				"/opt/activemq/lib",
				"/usr/share/activemq/lib",
			},
			regex: getMainJarRegex("activemq"),
		},
		{
			name: "spark",
			paths: []string{
				"/opt/spark/jars",
				"/usr/lib/spark/jars",
				"/usr/share/spark/jars",
			},
			regex: getMainJarRegex("spark"),
		},
	}

	for _, app := range jarPatterns {
		if strings.Contains(processNameLower, app.name) {
			logger.Debug("getJavaAppVersionFromJar: 匹配到应用: %s", app.name)
			for _, libPath := range app.paths {
				logger.Debug("getJavaAppVersionFromJar: 检查路径: %s", libPath)
				entries, err := os.ReadDir(libPath)
				if err != nil {
					logger.Debug("getJavaAppVersionFromJar: 路径不可读: %s, 错误: %v", libPath, err)
					continue
				}
				for _, entry := range entries {
					fileName := entry.Name()
					// 仅匹配主程序 jar/war
					if app.regex.MatchString(fileName) {
						if m := app.regex.FindStringSubmatch(fileName); len(m) > 1 {
							version := strings.TrimSpace(m[1])
							logger.Debug("getJavaAppVersionFromJar: 主程序文件名提取到版本: %s", version)
							return version
						}
						ext := strings.ToLower(filepath.Ext(fileName))
						if ext == ".jar" || ext == ".war" {
							jarPath := filepath.Join(libPath, fileName)
							if version := getVersionFromJarManifest(jarPath); version != "" {
								logger.Debug("getJavaAppVersionFromJar: 主程序 MANIFEST 获取到版本: %s", version)
								return version
							}
						}
					}
				}
			}
		}
	}

	logger.Debug("getJavaAppVersionFromJar: 无法从jar/war目录获取版本")
	return ""
}

// getJavaAppVersionFromConfig 从配置文件或目录获取版本
func getJavaAppVersionFromConfig(processName string, exePath string) string {
	logger.Debug("getJavaAppVersionFromConfig: 从配置获取进程 %s 的版本", processName)

	processNameLower := strings.ToLower(processName)

	// Elasticsearch: jar文件名或MANIFEST（Linux-only）
	if strings.Contains(processNameLower, "elasticsearch") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Elasticsearch配置方法")
		esLibPaths := []string{
			"/usr/share/elasticsearch/lib",
			"/opt/elasticsearch/lib",
			"/var/lib/elasticsearch/lib",
		}
		for _, libPath := range esLibPaths {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("elasticsearch")}, nil); version != "" {
				return version
			}
		}
	}

	// Kafka: libs目录
	if strings.Contains(processNameLower, "kafka") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Kafka配置方法")
		kafkaPaths := []string{
			"/opt/kafka/libs",
			"/usr/share/kafka/libs",
		}
		for _, libPath := range kafkaPaths {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("kafka")}, nil); version != "" {
				return version
			}
		}
	}

	// Logstash: logstash-core
	if strings.Contains(processNameLower, "logstash") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Logstash配置方法")
		logstashPaths := []string{
			filepath.Join("/opt/logstash", "logstash-core", "lib", "logstash-core"),
			filepath.Join("/usr/share/logstash", "logstash-core", "lib", "logstash-core"),
		}
		for _, coreLibPath := range logstashPaths {
			if version := findVersionInLibDirWithPriority(coreLibPath, []*regexp.Regexp{getMainJarRegex("logstash")}, nil); version != "" {
				return version
			}
		}
	}

	// Tomcat: catalina.jar
	if strings.Contains(processNameLower, "tomcat") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Tomcat配置方法")
		tomcatLibPaths := []string{
			"/usr/share/tomcat/lib",
			"/opt/tomcat/lib",
		}
		for _, libPath := range tomcatLibPaths {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("tomcat")}, nil); version != "" {
				return version
			}
		}
	}

	// Jenkins: jenkins.war
	if strings.Contains(processNameLower, "jenkins") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Jenkins配置方法")
		jenkinsPaths := []string{
			"/usr/share/jenkins",
			"/opt/jenkins",
			"/var/lib/jenkins",
		}
		for _, p := range jenkinsPaths {
			if version := findVersionInLibDirWithPriority(p, []*regexp.Regexp{getMainJarRegex("jenkins")}, nil); version != "" {
				return version
			}
		}
	}

	// Zookeeper: lib
	if strings.Contains(processNameLower, "zookeeper") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Zookeeper配置方法")
		zkLib := []string{
			"/usr/share/zookeeper/lib",
			"/opt/zookeeper/lib",
		}
		for _, libPath := range zkLib {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("zookeeper")}, nil); version != "" {
				return version
			}
		}
	}

	// Cassandra: lib
	if strings.Contains(processNameLower, "cassandra") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Cassandra配置方法")
		casLib := []string{
			"/usr/share/cassandra/lib",
			"/opt/cassandra/lib",
		}
		for _, libPath := range casLib {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("cassandra")}, nil); version != "" {
				return version
			}
		}
	}

	// Solr: server/lib
	if strings.Contains(processNameLower, "solr") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Solr配置方法")
		solrLib := []string{
			"/opt/solr/server/lib",
			"/usr/share/solr/server/lib",
		}
		for _, libPath := range solrLib {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("solr")}, nil); version != "" {
				return version
			}
		}
	}

	// Nexus: lib 目录
	if strings.Contains(processNameLower, "nexus") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Nexus配置方法")
		nexusLib := []string{
			"/opt/sonatype/nexus/lib",
			"/usr/share/sonatype/nexus/lib",
			"/usr/share/nexus/lib",
			"/opt/nexus/lib",
		}
		for _, libPath := range nexusLib {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("nexus")}, nil); version != "" {
				return version
			}
		}
	}

	// ActiveMQ: lib 目录
	if strings.Contains(processNameLower, "activemq") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试ActiveMQ配置方法")
		amqLib := []string{
			"/opt/activemq/lib",
			"/usr/share/activemq/lib",
		}
		for _, libPath := range amqLib {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("activemq")}, nil); version != "" {
				return version
			}
		}
	}

	// Spark: jars 目录
	if strings.Contains(processNameLower, "spark") {
		logger.Debug("getJavaAppVersionFromConfig: 尝试Spark配置方法")
		sparkJars := []string{
			"/opt/spark/jars",
			"/usr/lib/spark/jars",
			"/usr/share/spark/jars",
		}
		for _, libPath := range sparkJars {
			if version := findVersionInLibDirWithPriority(libPath, []*regexp.Regexp{getMainJarRegex("spark")}, nil); version != "" {
				return version
			}
		}
	}

	// 容器环境兜底：尝试获取镜像 tag 作为版本
	if version := getVersionFromContainerImage(processName); version != "" {
		logger.Debug("getJavaAppVersionFromConfig: 从容器镜像获取到版本: %s", version)
		return version
	}

	logger.Debug("getJavaAppVersionFromConfig: 未找到可用的配置来源")
	return ""
}

// getVersionFromContainerImage 尝试从容器镜像名提取版本号
func getVersionFromContainerImage(processName string) string {
	// 检查是否在容器内
	if !isRunningInContainer() {
		return ""
	}

	// 优先尝试 docker 环境变量
	if image := getDockerImageFromEnviron(); image != "" {
		if version := extractVersionFromImageTag(image, processName); version != "" {
			return version
		}
	}

	// 兜底尝试 docker inspect 当前容器ID
	if image := getDockerImageByInspect(); image != "" {
		if version := extractVersionFromImageTag(image, processName); version != "" {
			return version
		}
	}

	return ""
}

// isRunningInContainer 判断当前进程是否在容器内
func isRunningInContainer() bool {
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "docker") || strings.Contains(content, "kubepods") || strings.Contains(content, "containerd")
}

// getDockerImageFromEnviron 从环境变量中获取镜像名
func getDockerImageFromEnviron() string {
	data, err := os.ReadFile("/proc/1/environ")
	if err != nil {
		return ""
	}
	envs := strings.Split(string(data), "\x00")
	for _, env := range envs {
		if strings.HasPrefix(env, "DOCKER_IMAGE=") {
			return strings.TrimPrefix(env, "DOCKER_IMAGE=")
		}
		if strings.HasPrefix(env, "IMAGE_NAME=") {
			return strings.TrimPrefix(env, "IMAGE_NAME=")
		}
	}
	return ""
}

// getDockerImageByInspect 通过 docker inspect 获取当前容器镜像名
func getDockerImageByInspect() string {
	// 获取当前容器ID
	cid, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(cid), "\n")
	for _, line := range lines {
		parts := strings.Split(line, "/")
		if len(parts) > 2 {
			id := parts[len(parts)-1]
			if len(id) >= 12 {
				// docker inspect
				out, err := exec.Command("docker", "inspect", "--format", "{{.Config.Image}}", id).Output()
				if err == nil {
					return strings.TrimSpace(string(out))
				}
			}
		}
	}
	return ""
}

// extractVersionFromImageTag 从镜像名中提取 tag 作为版本
func extractVersionFromImageTag(image, processName string) string {
	// 例：elastic/elasticsearch:8.11.1
	parts := strings.Split(image, ":")
	if len(parts) == 2 && parts[1] != "" {
		return parts[1]
	}
	return ""
}

// helper: 提取 -Dxxx=yyy JVM 属性
func extractJavaPropsFromCmdLine(cmdLine string) map[string]string {
	props := make(map[string]string)
	// 匹配 -Dkey=value，其中 value 支持引号或无引号
	re := regexp.MustCompile(`-D([\w\.\-]+)=(".*?"|\S+)`)
	matches := re.FindAllStringSubmatch(cmdLine, -1)
	for _, m := range matches {
		key := strings.TrimSpace(m[1])
		val := strings.TrimSpace(m[2])
		val = strings.Trim(val, `"`)
		props[key] = val
	}
	return props
}

// helper: 提取 -cp/-classpath 的各个 classpath 项（Linux 使用 ':' 分隔）
func extractClasspathEntries(cmdLine string) []string {
	var entries []string
	// 支持引号与非引号两种写法
	re := regexp.MustCompile(`(?:^|\s)-(?:cp|classpath)\s+("[^"]+"|\S+)`)
	matches := re.FindAllStringSubmatch(cmdLine, -1)
	for _, m := range matches {
		cp := strings.TrimSpace(m[1])
		cp = strings.Trim(cp, `"`)
		if cp == "" {
			continue
		}
		// Linux 下以 ':' 分隔多个路径项
		parts := strings.Split(cp, ":")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				entries = append(entries, p)
			}
		}
	}
	return entries
}

// 获取真实应用名称（如 elasticsearch、kafka 等）。
// 规则：
// - 非 Java 进程：返回进程名（小写）。
// - Java 进程：按优先级进行识别：exe_path 包含应用名 -> 命令行包含主程序 jar -> classpath 目录/文件包含主程序 jar -> JVM 属性路径包含主程序 jar -> 最后返回 "java" 或 "unknown"。
func getProcessAppName(processName, exePath, cmdLine string) string {
    nameLower := strings.ToLower(strings.TrimSpace(processName))
    exeLower := strings.ToLower(strings.TrimSpace(exePath))

    // 非 Java 进程直接使用进程名
    if !isJavaProcess(processName) {
        if nameLower != "" {
            return nameLower
        }
        return "unknown"
    }

    // 1) 根据可执行路径快速识别（如 /usr/share/elasticsearch/jdk/bin/java）
    for app := range mainJarRegexTable {
        if strings.Contains(exeLower, app) {
            return app
        }
    }

    // 2) 命令行中直接包含主程序 jar/war 名称
    for app, re := range mainJarRegexTable {
        if re.MatchString(cmdLine) {
            return app
        }
    }

    // 3) 解析 -cp/-classpath 项，检查 jar 或目录内是否有主程序 jar
    cpEntries := extractClasspathEntries(cmdLine)
    if len(cpEntries) > 0 {
        for _, entry := range cpEntries {
            e := strings.TrimSpace(entry)
            if e == "" {
                continue
            }
            ext := strings.ToLower(filepath.Ext(e))
            if ext == ".jar" || ext == ".war" {
                base := filepath.Base(e)
                for app, re := range mainJarRegexTable {
                    if re.MatchString(base) {
                        return app
                    }
                }
            } else {
                // 视为目录，检查是否存在主程序 jar
                dir := e
                if strings.HasSuffix(dir, "/*") || strings.HasSuffix(dir, "\\*") {
                    dir = strings.TrimSuffix(dir, "/*")
                    dir = strings.TrimSuffix(dir, "\\*")
                }
                if app := findAppInDirByMainJar(dir); app != "" {
                    return app
                }
            }
        }
    }

    // 4) JVM 属性路径识别（与版本识别一致的路径模式）
    props := extractJavaPropsFromCmdLine(cmdLine)
    if home := firstNonEmpty(props["es.path.home"], props["path.home"]); home != "" {
        if app := findAppInDirByRegex(filepath.Join(home, "lib"), getMainJarRegex("elasticsearch")); app != "" { return app }
    }
    if home := props["logstash.home"]; home != "" {
        coreLib := filepath.Join(home, "logstash-core", "lib", "logstash-core")
        if app := findAppInDirByRegex(coreLib, getMainJarRegex("logstash")); app != "" { return app }
    }
    if home := firstNonEmpty(props["kafka.home"], props["kafka.base"]); home != "" {
        if app := findAppInDirByRegex(filepath.Join(home, "libs"), getMainJarRegex("kafka")); app != "" { return app }
    }
    if home := firstNonEmpty(props["catalina.base"], props["catalina.home"]); home != "" {
        if app := findAppInDirByRegex(filepath.Join(home, "lib"), getMainJarRegex("tomcat")); app != "" { return app }
    }
    if home := firstNonEmpty(props["jenkins.home"], props["JENKINS_HOME"]); home != "" {
        if app := findAppInDirByRegex(home, getMainJarRegex("jenkins")); app != "" { return app }
    }
    if home := props["zookeeper.home"]; home != "" {
        if app := findAppInDirByRegex(filepath.Join(home, "lib"), getMainJarRegex("zookeeper")); app != "" { return app }
    }
    if home := firstNonEmpty(props["cassandra.home"], props["cassandra.base"]); home != "" {
        if app := findAppInDirByRegex(filepath.Join(home, "lib"), getMainJarRegex("cassandra")); app != "" { return app }
    }
    if home := firstNonEmpty(props["solr.install.dir"], props["solr.home"]); home != "" {
        if app := findAppInDirByRegex(filepath.Join(home, "server", "lib"), getMainJarRegex("solr")); app != "" { return app }
        if app := findAppInDirByRegex(filepath.Join(home, "server", "solr", "lib"), getMainJarRegex("solr")); app != "" { return app }
    }

    // 5) 兜底：如果进程名包含已知应用名
    for app := range mainJarRegexTable {
        if strings.Contains(nameLower, app) {
            return app
        }
    }

    // 无法识别时返回 "java"
    if nameLower != "" {
        return nameLower
    }
    return "unknown"
}

// 在目录内检查是否存在任意主程序 jar，找到则返回应用名
func findAppInDirByMainJar(dir string) string {
    entries, err := os.ReadDir(dir)
    if err != nil {
        return ""
    }
    for _, entry := range entries {
        name := entry.Name()
        for app, re := range mainJarRegexTable {
            if re.MatchString(name) {
                return app
            }
        }
    }
    return ""
}

// 在目录内按特定应用的主程序正则查找，存在则返回该应用名
func findAppInDirByRegex(dir string, re *regexp.Regexp) string {
    if re == nil {
        return ""
    }
    entries, err := os.ReadDir(dir)
    if err != nil {
        return ""
    }
    for _, entry := range entries {
        if re.MatchString(entry.Name()) {
            return getAppNameByRegex(re)
        }
    }
    return ""
}

// 从正则对象反查应用名键（用于返回统一的小写应用名）
func getAppNameByRegex(re *regexp.Regexp) string {
    for app, r := range mainJarRegexTable {
        if r == re {
            return app
        }
    }
    return ""
}

// helper: 在给定目录内查找 jar/war 文件并优先解析主程序版本
// 集中维护：主程序 jar/war 文件名匹配正则
var mainJarRegexTable = map[string]*regexp.Regexp{
	"elasticsearch": regexp.MustCompile(`(?i)elasticsearch-([\d][\d\w\.-]+)\.jar`),
	"logstash":      regexp.MustCompile(`(?i)logstash-core-([\d][\d\w\.-]+)\.jar`),
	"kafka":         regexp.MustCompile(`(?i)kafka_[\d.]+-([\d][\d\w\.-]+)\.jar`),
	"tomcat":        regexp.MustCompile(`(?i)catalina\.jar`),
	"jenkins":       regexp.MustCompile(`(?i)jenkins\.war`),
	"zookeeper":     regexp.MustCompile(`(?i)zookeeper-([\d][\d\w\.-]+)\.jar`),
	"cassandra":     regexp.MustCompile(`(?i)cassandra-all-([\d][\d\w\.-]+)\.jar`),
	"solr":          regexp.MustCompile(`(?i)solr-core-([\d][\d\w\.-]+)\.jar`),
	// 扩展应用
	"nexus":    regexp.MustCompile(`(?i)(?:nexus|org\.sonatype\.nexus\.bootstrap)-([\d][\d\w\.-]+)\.(?:jar|war)`),
	"activemq": regexp.MustCompile(`(?i)activemq(?:-all|-broker|-client|-core)?-([\d][\d\w\.-]+)\.jar`),
	"spark":    regexp.MustCompile(`(?i)spark-core[_\d\.]*-([\d][\d\w\.-]+)\.jar`),
}

// 返回所有主程序正则，用于命令行与 classpath 扫描
func getAllMainJarRegexes() []*regexp.Regexp {
	regs := make([]*regexp.Regexp, 0, len(mainJarRegexTable))
	for _, r := range mainJarRegexTable {
		regs = append(regs, r)
	}
	return regs
}

// 根据应用名获取主程序正则（大小写不敏感）
func getMainJarRegex(app string) *regexp.Regexp {
	return mainJarRegexTable[strings.ToLower(app)]
}

func findVersionInLibDirWithPriority(libPath string, mainJarRegexes []*regexp.Regexp, fallbackJarRegex *regexp.Regexp) string {
	logger.Debug("findVersionInLibDirWithPriority: 扫描目录: %s", libPath)
	entries, err := os.ReadDir(libPath)
	if err != nil {
		logger.Debug("findVersionInLibDirWithPriority: 目录不可读: %v", err)
		return ""
	}
	// 优先遍历主程序 jar
	for _, mainRegex := range mainJarRegexes {
		for _, entry := range entries {
			name := entry.Name()
			if m := mainRegex.FindStringSubmatch(name); len(m) > 1 {
				version := strings.TrimSpace(m[1])
				logger.Debug("findVersionInLibDirWithPriority: 主程序 jar 从文件名提取到版本: %s", version)
				return version
			}
			// 如果是 jar/war，读取 MANIFEST
			ext := strings.ToLower(filepath.Ext(name))
			if ext == ".jar" || ext == ".war" {
				full := filepath.Join(libPath, name)
				if mainRegex.MatchString(name) {
					if version := getVersionFromJarManifest(full); version != "" {
						logger.Debug("findVersionInLibDirWithPriority: 主程序 jar 从 MANIFEST 获取到版本: %s", version)
						return version
					}
				}
			}
		}
	}
	// 主程序 jar 未找到时，兜底遍历依赖库 jar
	for _, entry := range entries {
		name := entry.Name()
		if fallbackJarRegex != nil {
			if m := fallbackJarRegex.FindStringSubmatch(name); len(m) > 1 {
				version := strings.TrimSpace(m[1])
				logger.Debug("findVersionInLibDirWithPriority: 依赖库 jar 从文件名提取到版本: %s", version)
				return version
			}
			ext := strings.ToLower(filepath.Ext(name))
			if ext == ".jar" || ext == ".war" {
				full := filepath.Join(libPath, name)
				if version := getVersionFromJarManifest(full); version != "" {
					logger.Debug("findVersionInLibDirWithPriority: 依赖库 jar 从 MANIFEST 获取到版本: %s", version)
					return version
				}
			}
		}
	}
	return ""
}

// helper: 返回第一个非空字符串
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
