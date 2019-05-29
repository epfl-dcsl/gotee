package work

import (
	"cmd/go/internal/load"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"text/template"
)

type Entry struct {
	Functions []string
	Imports   []string
}

const (
	gosectmpl = `
package main

import(
	"gosecu"
	//"runtime"
	{{range .Imports}}
	{{ printf "%q" . }}{{end}}
)

func main() {
	// Starting the functions.

	{{range .Functions}}

	gosecu.RegisterSecureFunction({{ . }})

	{{end}}
	gosecu.EcallServer()
}
`
)

// generateMain creates a temporary file _encl.o that corresponds contains
// a main with go calls to all the gosecure targets.
func generateMain(outfile string, functions, packages []string) string {
	if len(functions) == 0 {
		log.Fatalf("Missing target callees for gosecure keyword.")
	}

	if outfile == "" {
		log.Fatalf("Missing argument `outfile` for gosec command")
	}

	data := Entry{functions, packages}
	tmpl, err := template.New("gosec").Parse(gosectmpl)
	if tmpl == nil || err != nil {
		log.Fatalf(`gosec: parsing error "%s"`, err)
	}

	f, e := os.Create(outfile)
	defer f.Close()
	if e != nil {
		log.Fatalf(`gosec creating outfile failed: "%s"`, e)
	}

	if err = tmpl.Execute(f, data); err != nil {
		log.Fatalf(`"%s"`, err)
	}
	if _, err := os.Stat(outfile); os.IsNotExist(err) {
		log.Fatalf("The file doesn't exist.")
	}

	return outfile
}

// gosec generates calls generateMain to create the main go file for the enclave
// executable.
func (b *Builder) gosec(a *Action) (err error) {
	var functions, packages []string
	ofile := filepath.Dir(a.Objdir) + "encl.go"
	for p, m := range a.Package.PackagePublic.Gosectargets {
		if p == "main" {
			return fmt.Errorf("Invalid gosecure callee defined in main.")
		}
		packages = append(packages, p)
		if len(m) != 0 {
			for _, call := range m {
				functions = append(functions, p+"."+call)
			}
		}
	}
	fname := generateMain(ofile, functions, packages)
	if _, err := os.Stat(fname); os.IsNotExist(err) {
		return err
	}
	// Define the output dir.
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	efile := dir + "/enclave.out"
	args := []string{"-o", efile, "-relocencl", fname}
	cmd := CmdBuild
	cmd.Flag.Parse(args)
	args = cmd.Flag.Args()
	cmd.Run(cmd, args)
	a.Package.PackagePublic.Efile = efile
	return nil
}

// CreateEnclaveExec returns an Action that creates the temporary files necessary
// to create the enclave executable.
func (b *Builder) CreateEnclaveExec(p *load.Package) *Action {
	a := &Action{
		Mode:    "build",
		Package: p,
		Func:    (*Builder).gosec,
		Objdir:  b.NewObjdir(),
	}
	a.Target = a.Objdir + "_pkg_.a"
	a.built = a.Target
	return a
}
