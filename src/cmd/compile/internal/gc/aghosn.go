package gc

import (
	"cmd/compile/internal/types"
	"fmt"
)

type Loc int

const (
	Left Loc = iota
	Right
	Body
	Top
)

//For stringer
func (l Loc) String() string {
	switch l {
	case Left:
		return "Left"
	case Right:
		return "Right"
	case Body:
		return "Body"
	case Top:
		return "Top"
	default:
		return "UNKNOWN"
	}
}

type Pair struct {
	l Loc
	n *Node
}

func dumpEverything(n *Node) {
	s := fmt.Sprintf("left: %v, right: %v, Ninit: %v, Nbody: %v, ", n.Left, n.Right, n.Ninit, n.Nbody)
	s += fmt.Sprintf("List: %v, RList: %v\n", n.List, n.Rlist)
	s += fmt.Sprintf("Type: %v, Orig: %v, Func; %v, Name: %v\n", n.Type, n.Orig, n.Func, n.Name)
	s += fmt.Sprintf("Etype: %v, Op: %v\n", n.Etype, n.Op)

	fmt.Println(s)
}

func (p Pair) String() string {
	//s := fmt.Sprintf("(%v) %v, type: %v, name: %v, Op: %v\n", p.l, p.n, p.n.Type, p.n.funcname(), p.n.Op)
	s := fmt.Sprintf("(%v) %+v\n", p.l, p.n)
	return s
}

func walkGosecure(n *Node, path *[]*Pair) bool {
	if n == nil {
		return false
	}
	if n.Op == OGOSECURE {
		if len(*path) != 0 {
			*path = append([]*Pair{{Left, n.Left}}, *path...)
		} else {
			*path = []*Pair{{Left, n.Left}}
		}
		if n.Left == nil || n.Left.Op != OCALLFUNC {
			panic("Not a call functiona argument")
		}

		if n.Left.Left == nil || n.Left.Left.Op != ONAME {
			panic("Don't have the name for the call.")
		}

		return true
	}

	if walkGosecure(n.Left, path) {
		*path = append([]*Pair{{Left, n.Left}}, *path...)
		return true
	}

	if walkGosecure(n.Right, path) {
		*path = append([]*Pair{{Right, n.Left}}, *path...)
		return true
	}

	for _, b := range n.Nbody.Slice() {
		if walkGosecure(b, path) {
			*path = append([]*Pair{{Body, b}}, *path...)
			return true
		}
	}

	return false
}

func printPath(p []*Pair) {
	for i, n := range p {
		fmt.Printf("%v\n", n)
		if i == len(p)-1 {
			if n.n.Op != OCALLFUNC {
				panic("I'm not looking at the correct entry.")
			}
			//what is left of the occalfunc.
			if n.n.Left == nil {
				panic("Left of OCALLFUNC is null.")
			}

			//What is left of left.
			n1 := n.n.Left

			//The function declaration.
			decl := n1.Name.Defn

			//TODO aghosn: check the Func Inldcl how it is generated.
			//Can actually highjack inlining mech to do the copy.
			fmt.Printf("The func arg %+v\n", decl.Func)
		}
	}
}

func PrintLast(path []*Pair) {
	n := path[len(path)-1]
	if n == nil {
		panic("The last element is nil!")
	}
	fmt.Printf("The original node %+v\n", n)
	oname := n.n.Left.Name
	if oname == nil {
		panic("The name is null.")
	}
	//fmt.Printf("The address of defn (%p): %+v", oname.Defn, oname)

	decl := oname.Defn
	if decl == nil {
		fmt.Printf("%v\n", oname)
		panic("The declaration is null.")
	}
	//TODO aghosn: check the Func Inldcl how it is generated.
	//Can actually highjack inlining mech to do the copy.
	//fmt.Printf("The func arg %+v\n", decl.Func)
	//fmt.Printf("The name: %+v\n", decl.Func.Nname)
	//fmt.Printf("The original: %+v\n\n", decl)

	//TODO try to copy the shit out of the node.
	ncpy := inlcopy(decl)

	fmt.Printf("The oname: %v\n", *oname)
	fmt.Printf("The copy: %+v\n", ncpy)
	//fmt.Printf("The ninit and list %v, %v\n", ncpy.Ninit, ncpy.List)
}

func walking(n *Node, cond func(n *Node) bool, act func(n *Node)) {
	if n == nil {
		return
	}

	if cond(n) {
		act(n)
	}

	walking(n.Left, cond, act)
	walking(n.Right, cond, act)
	for _, e := range n.Ninit.Slice() {
		walking(e, cond, act)
	}
	for _, e := range n.Nbody.Slice() {
		walking(e, cond, act)
	}
	for _, e := range n.List.Slice() {
		walking(e, cond, act)
	}
	for _, e := range n.Rlist.Slice() {
		walking(e, cond, act)
	}
}

func conditionCALL(n *Node) bool {
	if n == nil {
		return false
	}
	return n.Op == OCALLFUNC
}

func actionDumpLCR(n *Node) {
	fmt.Printf("%v:\n", n)
	fmt.Printf("left: %v,right: %v\n", n.Left, n.Right)
	//if n.Left != nil {
	//	fmt.Printf("Op left: %v\n", n.Left.Op)
	//	oname := n.Left.Name
	//	if oname != nil {
	//		definition := oname.Defn
	//		if definition == nil {
	//			fmt.Println("definition cannot be resolved for this one.")
	//		} else {
	//			fmt.Printf("definition is %v\n", definition)
	//		}
	//	}
	//
	//}
}

func conditionLiteral(n *Node) bool {
	if n == nil {
		return false
	}

	return n.Op == OLITERAL
}

func ff(cond bool, s string) {
	if !cond {
		panic(s)
	}
}

func actionFindDef(n *Node) {
	if n == nil || n.Left == nil || n.Left.Name == nil {
		return
	}

	oname := n.Left.Name
	def := oname.Defn
	if def == nil {
		fmt.Printf("Definition unavailable for %v\n", tostring(n.Sym))
		return //TODO finish this after the course.
	}
	fmt.Println("------------------------------")
	fmt.Println(tostring(def.Sym))

}

func printImports() {
	fmt.Println("Printing the imports")
	imports := types.ImportedPkgList()
	for _, i := range imports {
		fmt.Println(i.Path)
	}
}

func tostring(s *types.Sym) string {
	if s == nil {
		return "<nil>"
	}

	return fmt.Sprintf("Name: %v, Linkname: %v", s.Name, s.Linkname)
}

func aghosnInspect(ttop []*Node) {
	for _, n := range ttop {
		walking(n, conditionCALL, actionFindDef)
	}

}

func findGoSecure(ttop []*Node) {
	for _, n := range ttop {
		path := make([]*Pair, 0, 1)
		if walkGosecure(n, &path) {
			path = append([]*Pair{{Top, n}}, path...)
			PrintLast(path)
		}
	}
}

// Saving old code.

// getFnDecl returns the callee corresponding to a function call.
//func getdFnDecl(n *Node) *Node {
//	if n.Left == nil || n.Left.Op != OCALLFUNC {
//		panic("GOSECURE: Not a call function argument.")
//	}
//	if n.Left.Left == nil || n.Left.Left.Op != ONAME {
//		panic("GOSECURE: Missing name for the gosecure callee.")
//	}
//	oname := n.Left.Name
//	if oname == nil || oname.Defn == nil {
//		panic("GOSECURE: Name or Defn node is nul.")
//	}
//	return oname.Defn
//}
//
//func walkerList(n Nodes, res *[]*Node) {
//	for _, b := range n.Slice() {
//		walker(b, res)
//	}
//}
//
//// walker walks an AST node and finds the gosecure calls.
//// It appends a copy of the declaration nodes corresponding to the callee
//// of the gosecure calls to the res slice.
////TODO aghosn should handle duplicates.
//func walker(n *Node, res *[]*Node) {
//	if n == nil {
//		return
//	}
//	//Found a gosecure call.
//	if n.Op == OGOSECURE {
//		fnDecl := getdFnDecl(n)
//		*res = append(*res, getCopy(fnDecl))
//		return
//	}
//
//	walker(n.Left, res)
//	walkerList(n.Ninit, res)
//	walkerList(n.Nbody, res)
//	walkerList(n.List, res)
//	walkerList(n.Rlist, res)
//	walker(n.Right, res)
//}

//func dumpAllNodeFields(n *Node) {
//	//fmt.Printf("%+v\n", n.Left)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.Right)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.Ninit)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.Nbody)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.List)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.List)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.Rlist)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.Type)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.Orig)
//	//fmt.Println(". . . . . . . .")
//	//fmt.Printf("%+v\n", n.Func)
//	fmt.Println("1. . . . . . . .")
//	fmt.Printf("%+v\n", n.Name)
//	fmt.Println("2. . . . . . . .")
//	fmt.Printf("%+v\n", n.Sym)
//	//	fmt.Println(". . . . . . . .")
//	//	fmt.Printf("%+v\n", n.E)
//	//	fmt.Println(". . . . . . . .")
//	//	fmt.Printf("%+v\n", n.Xoffset)
//	//	fmt.Println(". . . . . . . .")
//	//	fmt.Printf("%+v\n", n.Pos)
//	//	fmt.Println(". . . . . . . .")
//	//	fmt.Printf("%+v\n", n.flags)
//	//	fmt.Println(". . . . . . . .")
//	//	fmt.Printf("%+v\n", n.Esc)
//	//	fmt.Println(". . . . . . . .")
//	//	fmt.Printf("%+v\n", n.Op)
//	//	fmt.Println(". . . . . . . .")
//	//	fmt.Printf("%+v\n", n.Etype)
//}
