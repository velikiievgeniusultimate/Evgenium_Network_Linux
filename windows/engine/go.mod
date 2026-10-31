module evgenium.local/windows-engine

go 1.24

require (
	github.com/tailscale/wf v0.0.0-20240214030419-6fbb0a674ee6
	golang.org/x/sys v0.31.0
)

require (
	github.com/BurntSushi/toml v1.2.1 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/exp/typeparams v0.0.0-20221208152030-732eee02a75a // indirect
	golang.org/x/mod v0.10.0 // indirect
	golang.org/x/tools v0.9.4-0.20230601214343-86c93e8732cc // indirect
	honnef.co/go/tools v0.4.5 // indirect
)

replace github.com/tailscale/wf => ./wfp
