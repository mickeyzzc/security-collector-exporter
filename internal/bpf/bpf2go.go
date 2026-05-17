// Package bpf 包含 eBPF 程序和 Go 绑定。
//
// 使用 bpf2go 从 BPF C 程序生成 Go 绑定:
//
//	go generate ./internal/bpf/...
//
// 需要: clang, llvm, linux-headers
// 在 macOS 上通过 Docker 构建或在 Linux 上执行
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfebe BpfProcess ./sources/process.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfebe BpfNetwork ./sources/network.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfebe BpfFile ./sources/file.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfebe BpfPrivilege ./sources/privilege.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfebe BpfKernel ./sources/kernel.c
