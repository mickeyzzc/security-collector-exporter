package bpf

// process.c — 进程分类常量
const (
	ProcSystem     = 0 // 系统进程 (/usr/sbin, /usr/bin, /sbin, /bin)
	ProcUser       = 1 // 用户进程
	ProcContainer  = 2 // 容器进程（通过 cgroup 检测）
	ProcSuspicious = 3 // 可疑进程（shell/python/perl 等 + 非系统路径）
	ProcMaxCategory = 4
)

// process.c — 路径前缀长度
const PathPrefixLen = 16

// network.c — 网络方向常量
const (
	DirIn  = 0
	DirOut = 1
)

// network.c — 网络协议常量
const (
	ProtoTCP = 0
	ProtoUDP = 1
)

// network.c — 网络错误类型常量
const (
	ErrTimeout = 0
	ErrRefused = 1
	ErrReset   = 2
)

// network.c — TCP 状态常量（对应 kernel net/tcp_states.h）
const (
	TCPEstablished = 1
	TCPSynSent     = 2
	TCPSynRecv     = 3
	TCPFinWait1    = 4
	TCPFinWait2    = 5
	TCPTimeWait    = 6
	TCPClose       = 7
	TCPCloseWait   = 8
	TCPLastAck     = 9
)

// file.c — 文件严重级别常量
const (
	SeverityCritical = 0 // 关键文件：密码/影子文件
	SeverityWarning  = 1 // 警告文件：SSH/认证配置
	SeverityInfo     = 2 // 一般文件：系统配置
)

// file.c — 文件操作常量
const (
	OpRead  = 0 // 读操作
	OpWrite = 1 // 写操作
)

// file.c — 文件打开标志（与内核 O_RDONLY/O_WRONLY/O_RDWR 对应）
const (
	// O_RDONLY = 0  // 隐式零值
	O_WRONLY = 1
	O_RDWR   = 2
)

// file.c — map 最大条目数
const (
	FileMapMaxEntries = 6
)

// file.c — 路径最大长度
const PathMaxLen = 256

// privilege.c — 提权类型常量
const (
	TypeSetuid = 0
	TypeSetgid = 1
	TypeCapset = 2
)

// privilege.c — 提权结果常量
const (
	ResultSuccess = 0
	ResultFailure = 1
)

// kernel.c — 内核模块操作常量
const (
	ActionLoad     = 0 // init_module 系统调用（从内存缓冲区加载模块）
	ActionLoadFile = 1 // finit_module 系统调用（从文件描述符加载模块）
	ActionMax      = 2
)
