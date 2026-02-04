package buffer

import (
	"sync"
)

var TPool = sync.Pool{
	New: func() any {
		b := make([]byte, 128*1024) // 128 KB for fewer syscalls on high-throughput
		return &b
	},
}

var UPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024) // 64 KB for UDP packet aggregation
		return &b
	},
}
