package parser

import (
	"go/ast"
	"go/token"
)

// parseGosecCalls returns the stmt that contain the gosecure keyword.
// These are then stored in the File describing the package.
// We reload the source which is not efficient, but avoids modifying too much
// of the existing code.
// This function panics if called on a package that is not main.
func parseGosecCalls(fset *token.FileSet, filename string) (m map[string][]string) {
	bytes, err := readSource(filename, nil)
	if err != nil {
		panic(err)
	}

	var p parser
	var s []*ast.GosecStmt

	p.init(fset, filename, bytes, ImportsOnly|ParseComments)

	p.expect(token.PACKAGE)
	ident := p.parseIdent()

	if ident.Name != "main" {
		p.error(p.pos, "should not parse gosecure calls outside of package main.")
		return
	}

	for p.tok != token.EOF {
		if p.tok == token.GOSEC {
			a := p.parseGosecStmt().(*ast.GosecStmt)
			s = append(s, a)
		} else {
			p.next()
		}
	}

	if len(s) != 0 {
		m = make(map[string][]string)
	}

	// Convert to the expected output format.
	for _, e := range s {
		switch v := e.Call.Fun.(type) {
		case *ast.Ident:
			m["main"] = append(m["main"], v.Name)
		case *ast.SelectorExpr:
			n, ok := v.X.(*ast.Ident)
			if !ok || v.Sel == nil {
				p.error(v.Pos(), "invalid selector expression for gosecure call.")
				continue
			}
			m[n.Name] = append(m[n.Name], v.Sel.Name)
		default:
			p.error(v.Pos(), "Unable to verify the expression type for the gosecure callee.")
		}
	}

	return
}
