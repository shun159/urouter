module github.com/shun159/urouter

go 1.19

require (
	github.com/cilium/ebpf v0.10.0
	github.com/pkg/errors v0.9.1
)

require (
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/sys v0.2.0 // indirect
)

replace github.com/cilium/ebpf => ../ebpf
