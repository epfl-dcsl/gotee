// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import "sort"

// A Cache holds reusable compiler state.
// It is intended to be re-used for multiple Func compilations.
type Cache struct {
	// Storage for low-numbered values and blocks.
	values [2000]Value
	blocks [200]Block
	locs   [2000]Location

	// Storage for DWARF variable locations. Lazily allocated
	// since location lists are off by default.
	varLocs   []VarLoc
	curVarLoc int

	// Reusable stackAllocState.
	// See stackalloc.go's {new,put}StackAllocState.
	stackAllocState *stackAllocState

	domblockstore []ID         // scratch space for computing dominators
	scrSparse     []*sparseSet // scratch sparse sets to be re-used.
}

func (c *Cache) Reset() {
	nv := sort.Search(len(c.values), func(i int) bool { return c.values[i].ID == 0 })
	xv := c.values[:nv]
	for i := range xv {
		xv[i] = Value{}
	}
	nb := sort.Search(len(c.blocks), func(i int) bool { return c.blocks[i].ID == 0 })
	xb := c.blocks[:nb]
	for i := range xb {
		xb[i] = Block{}
	}
	nl := sort.Search(len(c.locs), func(i int) bool { return c.locs[i] == nil })
	xl := c.locs[:nl]
	for i := range xl {
		xl[i] = nil
	}
	xvl := c.varLocs[:c.curVarLoc]
	for i := range xvl {
		xvl[i] = VarLoc{}
	}
	c.curVarLoc = 0
}

func (c *Cache) NewVarLoc() *VarLoc {
	if c.varLocs == nil {
		c.varLocs = make([]VarLoc, 4000)
	}
	if c.curVarLoc == len(c.varLocs) {
		return &VarLoc{}
	}
	vl := &c.varLocs[c.curVarLoc]
	c.curVarLoc++
	return vl
}
