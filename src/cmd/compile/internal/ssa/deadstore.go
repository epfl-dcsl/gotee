// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/types"
	"cmd/internal/src"
)

// dse does dead-store elimination on the Function.
// Dead stores are those which are unconditionally followed by
// another store to the same location, with no intervening load.
// This implementation only works within a basic block. TODO: use something more global.
func dse(f *Func) {
	var stores []*Value
	loadUse := f.newSparseSet(f.NumValues())
	defer f.retSparseSet(loadUse)
	storeUse := f.newSparseSet(f.NumValues())
	defer f.retSparseSet(storeUse)
	shadowed := newSparseMap(f.NumValues()) // TODO: cache
	for _, b := range f.Blocks {
		// Find all the stores in this block. Categorize their uses:
		//  loadUse contains stores which are used by a subsequent load.
		//  storeUse contains stores which are used by a subsequent store.
		loadUse.clear()
		storeUse.clear()
		stores = stores[:0]
		for _, v := range b.Values {
			if v.Op == OpPhi {
				// Ignore phis - they will always be first and can't be eliminated
				continue
			}
			if v.Type.IsMemory() {
				stores = append(stores, v)
				for _, a := range v.Args {
					if a.Block == b && a.Type.IsMemory() {
						storeUse.add(a.ID)
						if v.Op != OpStore && v.Op != OpZero && v.Op != OpVarDef && v.Op != OpVarKill {
							// CALL, DUFFCOPY, etc. are both
							// reads and writes.
							loadUse.add(a.ID)
						}
					}
				}
			} else {
				for _, a := range v.Args {
					if a.Block == b && a.Type.IsMemory() {
						loadUse.add(a.ID)
					}
				}
			}
		}
		if len(stores) == 0 {
			continue
		}

		// find last store in the block
		var last *Value
		for _, v := range stores {
			if storeUse.contains(v.ID) {
				continue
			}
			if last != nil {
				b.Fatalf("two final stores - simultaneous live stores %s %s", last.LongString(), v.LongString())
			}
			last = v
		}
		if last == nil {
			b.Fatalf("no last store found - cycle?")
		}

		// Walk backwards looking for dead stores. Keep track of shadowed addresses.
		// An "address" is an SSA Value which encodes both the address and size of
		// the write. This code will not remove dead stores to the same address
		// of different types.
		shadowed.clear()
		v := last

	walkloop:
		if loadUse.contains(v.ID) {
			// Someone might be reading this memory state.
			// Clear all shadowed addresses.
			shadowed.clear()
		}
		if v.Op == OpStore || v.Op == OpZero {
			var sz int64
			if v.Op == OpStore {
				sz = v.Aux.(*types.Type).Size()
			} else { // OpZero
				sz = v.AuxInt
			}
			if shadowedSize := int64(shadowed.get(v.Args[0].ID)); shadowedSize != -1 && shadowedSize >= sz {
				// Modify store into a copy
				if v.Op == OpStore {
					// store addr value mem
					v.SetArgs1(v.Args[2])
				} else {
					// zero addr mem
					typesz := v.Args[0].Type.ElemType().Size()
					if sz != typesz {
						f.Fatalf("mismatched zero/store sizes: %d and %d [%s]",
							sz, typesz, v.LongString())
					}
					v.SetArgs1(v.Args[1])
				}
				v.Aux = nil
				v.AuxInt = 0
				v.Op = OpCopy
			} else {
				if sz > 0x7fffffff { // work around sparseMap's int32 value type
					sz = 0x7fffffff
				}
				shadowed.set(v.Args[0].ID, int32(sz), src.NoXPos)
			}
		}
		// walk to previous store
		if v.Op == OpPhi {
			// At start of block.  Move on to next block.
			// The memory phi, if it exists, is always
			// the first logical store in the block.
			// (Even if it isn't the first in the current b.Values order.)
			continue
		}
		for _, a := range v.Args {
			if a.Block == b && a.Type.IsMemory() {
				v = a
				goto walkloop
			}
		}
	}
}

// elimUnreadAutos deletes stores (and associated bookkeeping ops VarDef and VarKill)
// to autos that are never read from.
func elimUnreadAutos(f *Func) {
	// Loop over all ops that affect autos taking note of which
	// autos we need and also stores that we might be able to
	// eliminate.
	seen := make(map[GCNode]bool)
	var stores []*Value
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			n, ok := v.Aux.(GCNode)
			if !ok {
				continue
			}
			if n.StorageClass() != ClassAuto {
				continue
			}

			effect := v.Op.SymEffect()
			switch effect {
			case SymNone, SymWrite:
				// If we haven't seen the auto yet
				// then this might be a store we can
				// eliminate.
				if !seen[n] {
					stores = append(stores, v)
				}
			default:
				// Assume the auto is needed (loaded,
				// has its address taken, etc.).
				// Note we have to check the uses
				// because dead loads haven't been
				// eliminated yet.
				if v.Uses > 0 {
					seen[n] = true
				}
			}
		}
	}

	// Eliminate stores to unread autos.
	for _, store := range stores {
		n, _ := store.Aux.(GCNode)
		if seen[n] {
			continue
		}

		// replace store with OpCopy
		store.SetArgs1(store.MemoryArg())
		store.Aux = nil
		store.AuxInt = 0
		store.Op = OpCopy
	}
}
