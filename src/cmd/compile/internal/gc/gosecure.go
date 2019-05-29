package gc

// Global variables for the  current state.

// Contains the k: fndcl, v: list of call sites.
var targetMap map[*Node]Nodes

// Generic functions that I can instrument.

// genwalker is a generic walker for the Node type thgosecure callat visits all the children.
// It takes as parameter a cond func that decides whether or not to apply
// the act function on the node.
func genwalker(n *Node, cond func(n *Node) bool, act func(n *Node)) {
	if n == nil {
		return
	}
	if cond(n) {
		act(n)
	}
	genwalker(n.Left, cond, act)
	genwalker(n.Right, cond, act)
	genwalkerlist(n.Ninit, cond, act)
	genwalkerlist(n.Nbody, cond, act)
	genwalkerlist(n.List, cond, act)
	genwalkerlist(n.Rlist, cond, act)
}

// genwalkerlist is a simple helper to call genwalker on all Nodes in a slice.
func genwalkerlist(ns Nodes, cond func(n *Node) bool, act func(n *Node)) {
	for _, n := range ns.Slice() {
		genwalker(n, cond, act)
	}
}

// Implementation of the actually actions and conditions for gosecure.

// isGosecureNode returns true if Node n is a gosecure node, i.e.,
// if it has Op == OGOSECURE.
func isGosecureNode(n *Node) bool {
	if n == nil {
		return false
	}
	return n.Op == OGOSECURE
}

// findGosecureDef finds the callee of a gosecure node n.
func findGosecureDef(n *Node) {
	if n == nil {
		return
	}

	if _, ok := targetMap[n]; ok {
		yyerror("OGOSECURE node already in the map.")
		return
	}

	if n.Left == nil || n.Left.Left == nil || n.Left.Left.Name == nil {
		yyerror("OCALLFUNC or ONAME or Name node is nil in gosecure.")
		return
	}

	defn := n.Left.Left.Name.Defn
	if defn == nil {
		//The function is from another package.
		yyerror("Target of gosecure is in another package.")
	}
	entry := targetMap[defn]
	entry.Append(n)
}

// getCopy highjacks the inliner mechanism to generate a copy of the node.
func getCopy(n *Node) *Node {
	return inlcopy(n)
}

// Non generic version of the walker

func gosecureWalker(n *Node) {
	genwalker(n, isGosecureNode, findGosecureDef)
}

// findSecureNodes calls the walker on the ttop nodes.
func GosecurePhase(ttop []*Node) {
	if targetMap != nil {
		yyerror("The target map wasn't nil before starting.")
	}

	targetMap = make(map[*Node]Nodes)
	for _, n := range ttop {
		gosecureWalker(n)
	}

	// At that point we need to replace the targetMap with a copy.
	// TODO aghosn check memory and liveliness for code below.
	replacement := make(map[*Node]Nodes)
	for k, v := range targetMap {
		replacement[getCopy(k)] = v
	}
	targetMap = replacement

	// Package the code.
	// /enclpkg := obj.NewPkg("go.enclave", "enclave")
}
