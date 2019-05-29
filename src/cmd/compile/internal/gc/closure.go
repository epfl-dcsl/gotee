// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gc

import (
	"cmd/compile/internal/syntax"
	"cmd/compile/internal/types"
	"fmt"
)

func (p *noder) funcLit(expr *syntax.FuncLit) *Node {
	ntype := p.typeExpr(expr.Type)

	n := p.nod(expr, OCLOSURE, nil, nil)
	n.Func.SetIsHiddenClosure(Curfn != nil)
	n.Func.Ntype = ntype
	n.Func.Depth = funcdepth
	n.Func.Outerfunc = Curfn

	old := p.funchdr(n)

	// steal ntype's argument names and
	// leave a fresh copy in their place.
	// references to these variables need to
	// refer to the variables in the external
	// function declared below; see walkclosure.
	n.List.Set(ntype.List.Slice())
	n.Rlist.Set(ntype.Rlist.Slice())

	ntype.List.Set(nil)
	ntype.Rlist.Set(nil)
	for _, n1 := range n.List.Slice() {
		name := n1.Left
		if name != nil {
			name = newname(name.Sym)
		}
		a := nod(ODCLFIELD, name, n1.Right)
		a.SetIsddd(n1.Isddd())
		if name != nil {
			name.SetIsddd(a.Isddd())
		}
		ntype.List.Append(a)
	}
	for _, n2 := range n.Rlist.Slice() {
		name := n2.Left
		if name != nil {
			name = newname(name.Sym)
		}
		ntype.Rlist.Append(nod(ODCLFIELD, name, n2.Right))
	}

	body := p.stmts(expr.Body.List)

	lineno = Ctxt.PosTable.XPos(expr.Body.Rbrace)
	if len(body) == 0 {
		body = []*Node{nod(OEMPTY, nil, nil)}
	}

	n.Nbody.Set(body)
	n.Func.Endlineno = lineno
	p.funcbody(old)

	// closure-specific variables are hanging off the
	// ordinary ones in the symbol table; see oldname.
	// unhook them.
	// make the list of pointers for the closure call.
	for _, v := range n.Func.Cvars.Slice() {
		// Unlink from v1; see comment in syntax.go type Param for these fields.
		v1 := v.Name.Defn
		v1.Name.Param.Innermost = v.Name.Param.Outer

		// If the closure usage of v is not dense,
		// we need to make it dense; now that we're out
		// of the function in which v appeared,
		// look up v.Sym in the enclosing function
		// and keep it around for use in the compiled code.
		//
		// That is, suppose we just finished parsing the innermost
		// closure f4 in this code:
		//
		//	func f() {
		//		v := 1
		//		func() { // f2
		//			use(v)
		//			func() { // f3
		//				func() { // f4
		//					use(v)
		//				}()
		//			}()
		//		}()
		//	}
		//
		// At this point v.Outer is f2's v; there is no f3's v.
		// To construct the closure f4 from within f3,
		// we need to use f3's v and in this case we need to create f3's v.
		// We are now in the context of f3, so calling oldname(v.Sym)
		// obtains f3's v, creating it if necessary (as it is in the example).
		//
		// capturevars will decide whether to use v directly or &v.
		v.Name.Param.Outer = oldname(v.Sym)
	}

	return n
}

func typecheckclosure(func_ *Node, top int) {
	for _, ln := range func_.Func.Cvars.Slice() {
		n := ln.Name.Defn
		if !n.Name.Captured() {
			n.Name.SetCaptured(true)
			if n.Name.Decldepth == 0 {
				Fatalf("typecheckclosure: var %S does not have decldepth assigned", n)
			}

			// Ignore assignments to the variable in straightline code
			// preceding the first capturing by a closure.
			if n.Name.Decldepth == decldepth {
				n.SetAssigned(false)
			}
		}
	}

	for _, ln := range func_.Func.Dcl {
		if ln.Op == ONAME && (ln.Class() == PPARAM || ln.Class() == PPARAMOUT) {
			ln.Name.Decldepth = 1
		}
	}

	oldfn := Curfn
	func_.Func.Ntype = typecheck(func_.Func.Ntype, Etype)
	func_.Type = func_.Func.Ntype.Type
	func_.Func.Top = top

	// Type check the body now, but only if we're inside a function.
	// At top level (in a variable initialization: curfn==nil) we're not
	// ready to type check code yet; we'll check it later, because the
	// underlying closure function we create is added to xtop.
	if Curfn != nil && func_.Type != nil {
		Curfn = func_
		olddd := decldepth
		decldepth = 1
		typecheckslice(func_.Nbody.Slice(), Etop)
		decldepth = olddd
		Curfn = oldfn
	}

	// Create top-level function
	xtop = append(xtop, makeclosure(func_))
}

// closurename returns name for OCLOSURE n.
// It is not as simple as it ought to be, because we typecheck nested closures
// starting from the innermost one. So when we check the inner closure,
// we don't yet have name for the outer closure. This function uses recursion
// to generate names all the way up if necessary.

var closurename_closgen int

func closurename(n *Node) *types.Sym {
	if n.Sym != nil {
		return n.Sym
	}
	gen := 0
	outer := ""
	prefix := ""
	switch {
	case n.Func.Outerfunc == nil:
		// Global closure.
		outer = "glob."

		prefix = "func"
		closurename_closgen++
		gen = closurename_closgen
	case n.Func.Outerfunc.Op == ODCLFUNC:
		// The outermost closure inside of a named function.
		outer = n.Func.Outerfunc.funcname()

		prefix = "func"

		// Yes, functions can be named _.
		// Can't use function closgen in such case,
		// because it would lead to name clashes.
		if !isblank(n.Func.Outerfunc.Func.Nname) {
			n.Func.Outerfunc.Func.Closgen++
			gen = n.Func.Outerfunc.Func.Closgen
		} else {
			closurename_closgen++
			gen = closurename_closgen
		}
	case n.Func.Outerfunc.Op == OCLOSURE:
		// Nested closure, recurse.
		outer = closurename(n.Func.Outerfunc).Name

		prefix = ""
		n.Func.Outerfunc.Func.Closgen++
		gen = n.Func.Outerfunc.Func.Closgen
	default:
		Fatalf("closurename called for %S", n)
	}
	n.Sym = lookup(fmt.Sprintf("%s.%s%d", outer, prefix, gen))
	return n.Sym
}

func makeclosure(func_ *Node) *Node {
	// wrap body in external function
	// that begins by reading closure parameters.
	xtype := nod(OTFUNC, nil, nil)

	xtype.List.Set(func_.List.Slice())
	xtype.Rlist.Set(func_.Rlist.Slice())

	// create the function
	xfunc := nod(ODCLFUNC, nil, nil)
	xfunc.Func.SetIsHiddenClosure(Curfn != nil)

	xfunc.Func.Nname = newfuncname(closurename(func_))
	xfunc.Func.Nname.Sym.SetExported(true) // disable export
	xfunc.Func.Nname.Name.Param.Ntype = xtype
	xfunc.Func.Nname.Name.Defn = xfunc
	declare(xfunc.Func.Nname, PFUNC)
	xfunc.Func.Nname.Name.Funcdepth = func_.Func.Depth
	xfunc.Func.Depth = func_.Func.Depth
	xfunc.Func.Endlineno = func_.Func.Endlineno
	if Ctxt.Flag_dynlink {
		makefuncsym(xfunc.Func.Nname.Sym)
	}

	xfunc.Nbody.Set(func_.Nbody.Slice())
	xfunc.Func.Dcl = append(func_.Func.Dcl, xfunc.Func.Dcl...)
	xfunc.Func.Parents = func_.Func.Parents
	xfunc.Func.Marks = func_.Func.Marks
	func_.Func.Dcl = nil
	func_.Func.Parents = nil
	func_.Func.Marks = nil
	if xfunc.Nbody.Len() == 0 {
		Fatalf("empty body - won't generate any code")
	}
	xfunc = typecheck(xfunc, Etop)

	xfunc.Func.Closure = func_
	func_.Func.Closure = xfunc

	func_.Nbody.Set(nil)
	func_.List.Set(nil)
	func_.Rlist.Set(nil)

	return xfunc
}

// capturevarscomplete is set to true when the capturevars phase is done.
var capturevarscomplete bool

// capturevars is called in a separate phase after all typechecking is done.
// It decides whether each variable captured by a closure should be captured
// by value or by reference.
// We use value capturing for values <= 128 bytes that are never reassigned
// after capturing (effectively constant).
func capturevars(xfunc *Node) {
	lno := lineno
	lineno = xfunc.Pos

	func_ := xfunc.Func.Closure
	func_.Func.Enter.Set(nil)
	for _, v := range func_.Func.Cvars.Slice() {
		if v.Type == nil {
			// if v->type is nil, it means v looked like it was
			// going to be used in the closure but wasn't.
			// this happens because when parsing a, b, c := f()
			// the a, b, c gets parsed as references to older
			// a, b, c before the parser figures out this is a
			// declaration.
			v.Op = OXXX

			continue
		}

		// type check the & of closed variables outside the closure,
		// so that the outer frame also grabs them and knows they escape.
		dowidth(v.Type)

		outer := v.Name.Param.Outer
		outermost := v.Name.Defn

		// out parameters will be assigned to implicitly upon return.
		if outer.Class() != PPARAMOUT && !outermost.Addrtaken() && !outermost.Assigned() && v.Type.Width <= 128 {
			v.Name.SetByval(true)
		} else {
			outermost.SetAddrtaken(true)
			outer = nod(OADDR, outer, nil)
		}

		if Debug['m'] > 1 {
			var name *types.Sym
			if v.Name.Curfn != nil && v.Name.Curfn.Func.Nname != nil {
				name = v.Name.Curfn.Func.Nname.Sym
			}
			how := "ref"
			if v.Name.Byval() {
				how = "value"
			}
			Warnl(v.Pos, "%v capturing by %s: %v (addr=%v assign=%v width=%d)", name, how, v.Sym, outermost.Addrtaken(), outermost.Assigned(), int32(v.Type.Width))
		}

		outer = typecheck(outer, Erv)
		func_.Func.Enter.Append(outer)
	}

	lineno = lno
}

// transformclosure is called in a separate phase after escape analysis.
// It transform closure bodies to properly reference captured variables.
func transformclosure(xfunc *Node) {
	lno := lineno
	lineno = xfunc.Pos
	func_ := xfunc.Func.Closure

	if func_.Func.Top&Ecall != 0 {
		// If the closure is directly called, we transform it to a plain function call
		// with variables passed as args. This avoids allocation of a closure object.
		// Here we do only a part of the transformation. Walk of OCALLFUNC(OCLOSURE)
		// will complete the transformation later.
		// For illustration, the following closure:
		//	func(a int) {
		//		println(byval)
		//		byref++
		//	}(42)
		// becomes:
		//	func(byval int, &byref *int, a int) {
		//		println(byval)
		//		(*&byref)++
		//	}(byval, &byref, 42)

		// f is ONAME of the actual function.
		f := xfunc.Func.Nname

		// We are going to insert captured variables before input args.
		var params []*types.Field
		var decls []*Node
		for _, v := range func_.Func.Cvars.Slice() {
			if v.Op == OXXX {
				continue
			}
			fld := types.NewField()
			fld.Funarg = types.FunargParams
			if v.Name.Byval() {
				// If v is captured by value, we merely downgrade it to PPARAM.
				v.SetClass(PPARAM)
				fld.Nname = asTypesNode(v)
			} else {
				// If v of type T is captured by reference,
				// we introduce function param &v *T
				// and v remains PAUTOHEAP with &v heapaddr
				// (accesses will implicitly deref &v).
				addr := newname(lookup("&" + v.Sym.Name))
				addr.Type = types.NewPtr(v.Type)
				addr.SetClass(PPARAM)
				v.Name.Param.Heapaddr = addr
				fld.Nname = asTypesNode(addr)
			}

			fld.Type = asNode(fld.Nname).Type
			fld.Sym = asNode(fld.Nname).Sym

			params = append(params, fld)
			decls = append(decls, asNode(fld.Nname))
		}

		if len(params) > 0 {
			// Prepend params and decls.
			f.Type.Params().SetFields(append(params, f.Type.Params().FieldSlice()...))
			xfunc.Func.Dcl = append(decls, xfunc.Func.Dcl...)
		}

		dowidth(f.Type)
		xfunc.Type = f.Type // update type of ODCLFUNC
	} else {
		// The closure is not called, so it is going to stay as closure.
		var body []*Node
		offset := int64(Widthptr)
		for _, v := range func_.Func.Cvars.Slice() {
			if v.Op == OXXX {
				continue
			}

			// cv refers to the field inside of closure OSTRUCTLIT.
			cv := nod(OCLOSUREVAR, nil, nil)

			cv.Type = v.Type
			if !v.Name.Byval() {
				cv.Type = types.NewPtr(v.Type)
			}
			offset = Rnd(offset, int64(cv.Type.Align))
			cv.Xoffset = offset
			offset += cv.Type.Width

			if v.Name.Byval() && v.Type.Width <= int64(2*Widthptr) {
				// If it is a small variable captured by value, downgrade it to PAUTO.
				v.SetClass(PAUTO)
				xfunc.Func.Dcl = append(xfunc.Func.Dcl, v)
				body = append(body, nod(OAS, v, cv))
			} else {
				// Declare variable holding addresses taken from closure
				// and initialize in entry prologue.
				addr := newname(lookup("&" + v.Sym.Name))
				addr.Type = types.NewPtr(v.Type)
				addr.SetClass(PAUTO)
				addr.Name.SetUsed(true)
				addr.Name.Curfn = xfunc
				xfunc.Func.Dcl = append(xfunc.Func.Dcl, addr)
				v.Name.Param.Heapaddr = addr
				if v.Name.Byval() {
					cv = nod(OADDR, cv, nil)
				}
				body = append(body, nod(OAS, addr, cv))
			}
		}

		if len(body) > 0 {
			typecheckslice(body, Etop)
			walkstmtlist(body)
			xfunc.Func.Enter.Set(body)
			xfunc.Func.SetNeedctxt(true)
		}
	}

	lineno = lno
}

// hasemptycvars returns true iff closure func_ has an
// empty list of captured vars. OXXX nodes don't count.
func hasemptycvars(func_ *Node) bool {
	for _, v := range func_.Func.Cvars.Slice() {
		if v.Op == OXXX {
			continue
		}
		return false
	}
	return true
}

// closuredebugruntimecheck applies boilerplate checks for debug flags
// and compiling runtime
func closuredebugruntimecheck(r *Node) {
	if Debug_closure > 0 {
		if r.Esc == EscHeap {
			Warnl(r.Pos, "heap closure, captured vars = %v", r.Func.Cvars)
		} else {
			Warnl(r.Pos, "stack closure, captured vars = %v", r.Func.Cvars)
		}
	}
	if compiling_runtime && r.Esc == EscHeap {
		yyerrorl(r.Pos, "heap-allocated closure, not allowed in runtime.")
	}
}

func walkclosure(func_ *Node, init *Nodes) *Node {
	// If no closure vars, don't bother wrapping.
	if hasemptycvars(func_) {
		if Debug_closure > 0 {
			Warnl(func_.Pos, "closure converted to global")
		}
		return func_.Func.Closure.Func.Nname
	}
	closuredebugruntimecheck(func_)

	// Create closure in the form of a composite literal.
	// supposing the closure captures an int i and a string s
	// and has one float64 argument and no results,
	// the generated code looks like:
	//
	//	clos = &struct{.F uintptr; i *int; s *string}{func.1, &i, &s}
	//
	// The use of the struct provides type information to the garbage
	// collector so that it can walk the closure. We could use (in this case)
	// [3]unsafe.Pointer instead, but that would leave the gc in the dark.
	// The information appears in the binary in the form of type descriptors;
	// the struct is unnamed so that closures in multiple packages with the
	// same struct type can share the descriptor.

	fields := []*Node{
		namedfield(".F", types.Types[TUINTPTR]),
	}
	for _, v := range func_.Func.Cvars.Slice() {
		if v.Op == OXXX {
			continue
		}
		typ := v.Type
		if !v.Name.Byval() {
			typ = types.NewPtr(typ)
		}
		fields = append(fields, symfield(v.Sym, typ))
	}
	typ := tostruct(fields)
	typ.SetNoalg(true)

	clos := nod(OCOMPLIT, nil, nod(OIND, typenod(typ), nil))
	clos.Esc = func_.Esc
	clos.Right.SetImplicit(true)
	clos.List.Set(append([]*Node{nod(OCFUNC, func_.Func.Closure.Func.Nname, nil)}, func_.Func.Enter.Slice()...))

	// Force type conversion from *struct to the func type.
	clos = nod(OCONVNOP, clos, nil)
	clos.Type = func_.Type

	clos = typecheck(clos, Erv)

	// typecheck will insert a PTRLIT node under CONVNOP,
	// tag it with escape analysis result.
	clos.Left.Esc = func_.Esc

	// non-escaping temp to use, if any.
	// orderexpr did not compute the type; fill it in now.
	if x := prealloc[func_]; x != nil {
		x.Type = clos.Left.Left.Type
		x.Orig.Type = x.Type
		clos.Left.Right = x
		delete(prealloc, func_)
	}

	return walkexpr(clos, init)
}

func typecheckpartialcall(fn *Node, sym *types.Sym) {
	switch fn.Op {
	case ODOTINTER, ODOTMETH:
		break

	default:
		Fatalf("invalid typecheckpartialcall")
	}

	// Create top-level function.
	xfunc := makepartialcall(fn, fn.Type, sym)
	fn.Func = xfunc.Func
	fn.Right = newname(sym)
	fn.Op = OCALLPART
	fn.Type = xfunc.Type
}

var makepartialcall_gopkg *types.Pkg

func makepartialcall(fn *Node, t0 *types.Type, meth *types.Sym) *Node {
	var p string

	rcvrtype := fn.Left.Type
	if exportname(meth.Name) {
		p = fmt.Sprintf("(%-S).%s-fm", rcvrtype, meth.Name)
	} else {
		p = fmt.Sprintf("(%-S).(%-v)-fm", rcvrtype, meth)
	}
	basetype := rcvrtype
	if rcvrtype.IsPtr() {
		basetype = basetype.Elem()
	}
	if !basetype.IsInterface() && basetype.Sym == nil {
		Fatalf("missing base type for %v", rcvrtype)
	}

	var spkg *types.Pkg
	if basetype.Sym != nil {
		spkg = basetype.Sym.Pkg
	}
	if spkg == nil {
		if makepartialcall_gopkg == nil {
			makepartialcall_gopkg = types.NewPkg("go", "")
		}
		spkg = makepartialcall_gopkg
	}

	sym := spkg.Lookup(p)

	if sym.Uniq() {
		return asNode(sym.Def)
	}
	sym.SetUniq(true)

	savecurfn := Curfn
	Curfn = nil

	xtype := nod(OTFUNC, nil, nil)
	var l []*Node
	var callargs []*Node
	ddd := false
	xfunc := nod(ODCLFUNC, nil, nil)
	Curfn = xfunc
	for i, t := range t0.Params().Fields().Slice() {
		n := newname(lookupN("a", i))
		n.SetClass(PPARAM)
		xfunc.Func.Dcl = append(xfunc.Func.Dcl, n)
		callargs = append(callargs, n)
		fld := nod(ODCLFIELD, n, typenod(t.Type))
		if t.Isddd() {
			fld.SetIsddd(true)
			ddd = true
		}

		l = append(l, fld)
	}

	xtype.List.Set(l)
	l = nil
	var retargs []*Node
	for i, t := range t0.Results().Fields().Slice() {
		n := newname(lookupN("r", i))
		n.SetClass(PPARAMOUT)
		xfunc.Func.Dcl = append(xfunc.Func.Dcl, n)
		retargs = append(retargs, n)
		l = append(l, nod(ODCLFIELD, n, typenod(t.Type)))
	}

	xtype.Rlist.Set(l)

	xfunc.Func.SetDupok(true)
	xfunc.Func.Nname = newfuncname(sym)
	xfunc.Func.Nname.Sym.SetExported(true) // disable export
	xfunc.Func.Nname.Name.Param.Ntype = xtype
	xfunc.Func.Nname.Name.Defn = xfunc
	declare(xfunc.Func.Nname, PFUNC)

	// Declare and initialize variable holding receiver.

	xfunc.Func.SetNeedctxt(true)
	cv := nod(OCLOSUREVAR, nil, nil)
	cv.Xoffset = int64(Widthptr)
	cv.Type = rcvrtype
	if int(cv.Type.Align) > Widthptr {
		cv.Xoffset = int64(cv.Type.Align)
	}
	ptr := newname(lookup("rcvr"))
	ptr.SetClass(PAUTO)
	ptr.Name.SetUsed(true)
	ptr.Name.Curfn = xfunc
	xfunc.Func.Dcl = append(xfunc.Func.Dcl, ptr)
	var body []*Node
	if rcvrtype.IsPtr() || rcvrtype.IsInterface() {
		ptr.Type = rcvrtype
		body = append(body, nod(OAS, ptr, cv))
	} else {
		ptr.Type = types.NewPtr(rcvrtype)
		body = append(body, nod(OAS, ptr, nod(OADDR, cv, nil)))
	}

	call := nod(OCALL, nodSym(OXDOT, ptr, meth), nil)
	call.List.Set(callargs)
	call.SetIsddd(ddd)
	if t0.NumResults() == 0 {
		body = append(body, call)
	} else {
		n := nod(OAS2, nil, nil)
		n.List.Set(retargs)
		n.Rlist.Set1(call)
		body = append(body, n)
		n = nod(ORETURN, nil, nil)
		body = append(body, n)
	}

	xfunc.Nbody.Set(body)

	xfunc = typecheck(xfunc, Etop)
	sym.Def = asTypesNode(xfunc)
	xtop = append(xtop, xfunc)
	Curfn = savecurfn

	return xfunc
}

func walkpartialcall(n *Node, init *Nodes) *Node {
	// Create closure in the form of a composite literal.
	// For x.M with receiver (x) type T, the generated code looks like:
	//
	//	clos = &struct{F uintptr; R T}{M.T·f, x}
	//
	// Like walkclosure above.

	if n.Left.Type.IsInterface() {
		// Trigger panic for method on nil interface now.
		// Otherwise it happens in the wrapper and is confusing.
		n.Left = cheapexpr(n.Left, init)

		checknil(n.Left, init)
	}

	typ := tostruct([]*Node{
		namedfield("F", types.Types[TUINTPTR]),
		namedfield("R", n.Left.Type),
	})
	typ.SetNoalg(true)

	clos := nod(OCOMPLIT, nil, nod(OIND, typenod(typ), nil))
	clos.Esc = n.Esc
	clos.Right.SetImplicit(true)
	clos.List.Set1(nod(OCFUNC, n.Func.Nname, nil))
	clos.List.Append(n.Left)

	// Force type conversion from *struct to the func type.
	clos = nod(OCONVNOP, clos, nil)
	clos.Type = n.Type

	clos = typecheck(clos, Erv)

	// typecheck will insert a PTRLIT node under CONVNOP,
	// tag it with escape analysis result.
	clos.Left.Esc = n.Esc

	// non-escaping temp to use, if any.
	// orderexpr did not compute the type; fill it in now.
	if x := prealloc[n]; x != nil {
		x.Type = clos.Left.Left.Type
		x.Orig.Type = x.Type
		clos.Left.Right = x
		delete(prealloc, n)
	}

	return walkexpr(clos, init)
}
