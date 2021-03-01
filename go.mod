module github.com/eycorsican/go-tun2socks

go 1.15

require (
	github.com/kayrus/tuncfg v0.0.0-20210306071952-3921bb103b0a
	golang.org/x/net v0.0.0-20210224082022-3d97a244fca7
	golang.org/x/sys v0.0.0-20210303074136-134d130e1a04
)

// a fork with a FreeBSD default tun name patch
replace golang.zx2c4.com/wireguard v0.0.0-20210225140808-70b7b7158fc9 => github.com/kayrus/wireguard v0.0.0-20210228102730-04afc3c4c795

// a fork with a Windows convertInterfaceIndexToLUID
replace golang.zx2c4.com/wireguard/windows v0.3.8 => github.com/kayrus/wireguard-windows v0.0.0-20210303100507-540e87897140
