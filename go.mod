module github.com/eycorsican/go-tun2socks

go 1.15

require (
	github.com/IBM/netaddr v1.4.0
	github.com/stretchr/testify v1.6.1 // indirect
	github.com/vishvananda/netlink v1.1.0
	golang.org/x/net v0.0.0-20210224082022-3d97a244fca7
	golang.org/x/sys v0.0.0-20210225014209-683adc9d29d7
	golang.zx2c4.com/wireguard v0.0.0-20210225140808-70b7b7158fc9
)

// a fork with a FreeBSD default tun name patch
replace golang.zx2c4.com/wireguard v0.0.0-20210225140808-70b7b7158fc9 => github.com/kayrus/wireguard v0.0.0-20210228102730-04afc3c4c795
