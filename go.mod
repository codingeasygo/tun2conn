module github.com/codingeasygo/tun2conn

go 1.21.1

toolchain go1.21.4

require (
	github.com/codingeasygo/util v0.0.0-20231202034448-7e31a61c18d8
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	golang.org/x/net v0.19.0
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/time v0.3.0 // indirect
)

// replace gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 => github.com/codingeasygo/gvisor v0.0.0-20231202131929-2167d0e868f3

replace gvisor.dev/gvisor => /Users/cny/work/gvisor
