package main

import "github.com/learn-decentralized-systems/toytlv"

func LState(link id64, time uint64) []byte {
	return toytlv.Record('L',
		toytlv.Record('T', ZipUint64(time)),
		link.ZipBytes(),
	)
}
