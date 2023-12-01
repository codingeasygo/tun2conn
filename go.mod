module github.com/codingeasygo/tun2conn

go 1.21.1

toolchain go1.21.4

replace gvisor.dev/gvisor v0.0.0-20231130224249-b850869d6e9a => github.com/codingeasygo/gvisor v0.0.0-20231130102452-155e41312091

require (
	github.com/codingeasygo/util v0.0.0-20231111050333-a0cfbf0935e9
	golang.org/x/net v0.19.0
	gvisor.dev/gvisor v0.0.0-20231130224249-b850869d6e9a
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/time v0.3.0 // indirect
)
