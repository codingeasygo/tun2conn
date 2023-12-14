module github.com/codingeasygo/tun2conn

go 1.21.1

toolchain go1.21.4

require (
	github.com/codingeasygo/util v0.0.0-20231206062002-1ce2f004b7d9
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	golang.org/x/net v0.19.0
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/time v0.3.0 // indirect
)

replace gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 => github.com/codingeasygo/gvisor v0.0.0-20231203111534-4a1d1d9214fa
