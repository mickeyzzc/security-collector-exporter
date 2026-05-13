package system

import (
	"regexp"
	"testing"
)

func TestExtractVersionFromImageTag(t *testing.T) {
	tests := []struct {
		image    string
		name     string
		expected string
	}{
		{"openjdk:8u342", "java", "8u342"},
		{"tomcat:9.0.65-jdk11", "tomcat", "9.0.65-jdk11"},
		{"nginx:latest", "nginx", "latest"},
		{"myapp:v1.2.3", "myapp", "v1.2.3"},
		{"busybox", "busybox", ""},
		{"repo:image", "app", "image"},
	}
	for _, tc := range tests {
		got := extractVersionFromImageTag(tc.image, tc.name)
		if got != tc.expected {
			t.Errorf("extractVersionFromImageTag(%q, %q) = %q, want %q", tc.image, tc.name, got, tc.expected)
		}
	}
}

func TestExtractJavaPropsFromCmdLine(t *testing.T) {
	tests := []struct {
		name     string
		cmdLine  string
		expected map[string]string
	}{
		{
			name:     "basic props",
			cmdLine:  `-Dserver.port=8080 -Dspring.profiles.active=prod`,
			expected: map[string]string{"server.port": "8080", "spring.profiles.active": "prod"},
		},
		{
			name:     "quoted value",
			cmdLine:  `-Dapp.name="my app" -Denv=dev`,
			expected: map[string]string{"app.name": "my app", "env": "dev"},
		},
		{
			name:     "empty",
			cmdLine:  ``,
			expected: map[string]string{},
		},
		{
			name:     "no D flags",
			cmdLine:  `-Xmx512m -Xms256m`,
			expected: map[string]string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractJavaPropsFromCmdLine(tc.cmdLine)
			if len(got) != len(tc.expected) {
				t.Fatalf("got %d props, want %d; got=%v want=%v", len(got), len(tc.expected), got, tc.expected)
			}
			for k, v := range tc.expected {
				if got[k] != v {
					t.Errorf("props[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestExtractClasspathEntries(t *testing.T) {
	tests := []struct {
		name     string
		cmdLine  string
		expected []string
	}{
		{
			name:     "colon separated",
			cmdLine:  `-cp /a.jar:/b.jar com.example.Main`,
			expected: []string{"/a.jar", "/b.jar"},
		},
		{
			name:     "classpath flag",
			cmdLine:  `-classpath /x.jar:/y.jar:/z.jar com.example.App`,
			expected: []string{"/x.jar", "/y.jar", "/z.jar"},
		},
		{
			name:     "no classpath",
			cmdLine:  `-Xmx512m com.example.Main`,
			expected: nil,
		},
		{
			name:     "quoted classpath",
			cmdLine:  `-cp "/long path/a.jar:/long path/b.jar" com.example.Main`,
			expected: []string{"/long path/a.jar", "/long path/b.jar"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractClasspathEntries(tc.cmdLine)
			if len(got) != len(tc.expected) {
				t.Fatalf("got %v, want %v", got, tc.expected)
			}
			for i, v := range got {
				if v != tc.expected[i] {
					t.Errorf("entry[%d] = %q, want %q", i, v, tc.expected[i])
				}
			}
		})
	}
}

func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		values   []string
		expected string
	}{
		{[]string{"", "hello", "world"}, "hello"},
		{[]string{"first", "second"}, "first"},
		{[]string{"", "", ""}, ""},
		{[]string{}, ""},
		{[]string{"", "  ", "value"}, "value"},
		{[]string{"abc"}, "abc"},
	}
	for _, tc := range tests {
		got := firstNonEmpty(tc.values...)
		if got != tc.expected {
			t.Errorf("firstNonEmpty(%v) = %q, want %q", tc.values, got, tc.expected)
		}
	}
}

func TestIsJavaProcess(t *testing.T) {
	javaNames := []string{"java", "javaw", "elasticsearch", "kafka", "logstash", "tomcat", "jenkins", "zookeeper", "solr", "cassandra", "hadoop"}
	for _, name := range javaNames {
		if !isJavaProcess(name) {
			t.Errorf("isJavaProcess(%q) = false, want true", name)
		}
	}
	nonJava := []string{"nginx", "redis-server", "mysqld", "postgres", "docker"}
	for _, name := range nonJava {
		if isJavaProcess(name) {
			t.Errorf("isJavaProcess(%q) = true, want false", name)
		}
	}
}

func TestMainJarRegexTable(t *testing.T) {
	tests := []struct {
		app      string
		filename string
		matches  bool
	}{
		{"elasticsearch", "elasticsearch-8.11.1.jar", true},
		{"elasticsearch", "Elasticsearch-7.17.0.jar", true},
		{"elasticsearch", "other-lib.jar", false},
		{"logstash", "logstash-core-8.11.1.jar", true},
		{"kafka", "kafka_2.13-3.6.0.jar", true},
		{"tomcat", "catalina.jar", true},
		{"jenkins", "jenkins.war", true},
		{"zookeeper", "zookeeper-3.9.1.jar", true},
		{"cassandra", "cassandra-all-5.0.jar", true},
		{"solr", "solr-core-9.4.0.jar", true},
	}
	for _, tc := range tests {
		t.Run(tc.app+"/"+tc.filename, func(t *testing.T) {
			re := getMainJarRegex(tc.app)
			if re == nil {
				t.Fatalf("getMainJarRegex(%q) returned nil", tc.app)
			}
			got := re.MatchString(tc.filename)
			if got != tc.matches {
				t.Errorf("regex for %q matching %q = %v, want %v", tc.app, tc.filename, got, tc.matches)
			}
		})
	}
}

func TestGetAllMainJarRegexes(t *testing.T) {
	regexes := getAllMainJarRegexes()
	if len(regexes) == 0 {
		t.Fatal("getAllMainJarRegexes() returned empty slice")
	}
	for _, re := range regexes {
		if re == nil {
			t.Error("getAllMainJarRegexes() returned nil regexp")
		}
	}
}

func TestGetAppNameByRegex(t *testing.T) {
	for app, re := range mainJarRegexTable {
		got := getAppNameByRegex(re)
		if got != app {
			t.Errorf("getAppNameByRegex for %q regex returned %q, want %q", app, got, app)
		}
	}
	got := getAppNameByRegex(regexp.MustCompile(`nonexistent`))
	if got != "" {
		t.Errorf("getAppNameByRegex for unknown regex returned %q, want empty", got)
	}
}

func TestGetProcessAppName(t *testing.T) {
	tests := []struct {
		name     string
		pName    string
		exePath  string
		cmdLine  string
		expected string
	}{
		{"non-java nginx", "nginx", "/usr/sbin/nginx", "", "nginx"},
		{"non-java redis", "redis-server", "/usr/bin/redis-server", "", "redis-server"},
		{"empty name", "", "", "", "unknown"},
		{"java with exe path", "java", "/usr/share/elasticsearch/jdk/bin/java", "", "elasticsearch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getProcessAppName(tc.pName, tc.exePath, tc.cmdLine)
			if got != tc.expected {
				t.Errorf("getProcessAppName(%q, %q, %q) = %q, want %q", tc.pName, tc.exePath, tc.cmdLine, got, tc.expected)
			}
		})
	}
}
