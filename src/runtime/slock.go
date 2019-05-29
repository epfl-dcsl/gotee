package runtime

import (
	"runtime/internal/atomic"
)

type slock struct {
	key uint32
}

//go:nosplit
func (l *slock) lock() {
	for {
		for i := 0; i < active_spin_cnt; i++ {
			if l.key == mutex_unlocked {
				if atomic.Cas(&l.key, mutex_unlocked, mutex_locked) {
					return
				}
			}
		}
		procyield(15)
	}
}

//go:nosplit
func (l *slock) unlock() {
	if v := atomic.Xchg(&l.key, mutex_unlocked); v != mutex_locked {
		throw("Error on spinlock.")
	}
}
