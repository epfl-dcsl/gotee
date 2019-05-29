// skip

// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Run runs tests in the test directory.
//
// TODO(bradfitz): docs of some sort, once we figure out how we're changing
// headers of files
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	verbose        = flag.Bool("v", false, "verbose. if set, parallelism is set to 1.")
	keep           = flag.Bool("k", false, "keep. keep temporary directory.")
	numParallel    = flag.Int("n", runtime.NumCPU(), "number of parallel tests to run")
	summary        = flag.Bool("summary", false, "show summary of results")
	showSkips      = flag.Bool("show_skips", false, "show skipped tests")
	runSkips       = flag.Bool("run_skips", false, "run skipped tests (ignore skip and build tags)")
	linkshared     = flag.Bool("linkshared", false, "")
	updateErrors   = flag.Bool("update_errors", false, "update error messages in test file based on compiler output")
	runoutputLimit = flag.Int("l", defaultRunOutputLimit(), "number of parallel runoutput tests to run")

	shard  = flag.Int("shard", 0, "shard index to run. Only applicable if -shards is non-zero.")
	shards = flag.Int("shards", 0, "number of shards. If 0, all tests are run. This is used by the continuous build.")
)

var (
	goos, goarch string

	// dirs are the directories to look for *.go files in.
	// TODO(bradfitz): just use all directories?
	dirs = []string{".", "ken", "chan", "interface", "syntax", "dwarf", "fixedbugs"}

	// ratec controls the max number of tests running at a time.
	ratec chan bool

	// toRun is the channel of tests to run.
	// It is nil until the first test is started.
	toRun chan *test

	// rungatec controls the max number of runoutput tests
	// executed in parallel as they can each consume a lot of memory.
	rungatec chan bool
)

// maxTests is an upper bound on the total number of tests.
// It is used as a channel buffer size to make sure sends don't block.
const maxTests = 5000

func main() {
	flag.Parse()

	goos = getenv("GOOS", runtime.GOOS)
	goarch = getenv("GOARCH", runtime.GOARCH)

	findExecCmd()

	// Disable parallelism if printing or if using a simulator.
	if *verbose || len(findExecCmd()) > 0 {
		*numParallel = 1
	}

	ratec = make(chan bool, *numParallel)
	rungatec = make(chan bool, *runoutputLimit)

	var tests []*test
	if flag.NArg() > 0 {
		for _, arg := range flag.Args() {
			if arg == "-" || arg == "--" {
				// Permit running:
				// $ go run run.go - env.go
				// $ go run run.go -- env.go
				// $ go run run.go - ./fixedbugs
				// $ go run run.go -- ./fixedbugs
				continue
			}
			if fi, err := os.Stat(arg); err == nil && fi.IsDir() {
				for _, baseGoFile := range goFiles(arg) {
					tests = append(tests, startTest(arg, baseGoFile))
				}
			} else if strings.HasSuffix(arg, ".go") {
				dir, file := filepath.Split(arg)
				tests = append(tests, startTest(dir, file))
			} else {
				log.Fatalf("can't yet deal with non-directory and non-go file %q", arg)
			}
		}
	} else {
		for _, dir := range dirs {
			for _, baseGoFile := range goFiles(dir) {
				tests = append(tests, startTest(dir, baseGoFile))
			}
		}
	}

	failed := false
	resCount := map[string]int{}
	for _, test := range tests {
		<-test.donec
		status := "ok  "
		errStr := ""
		if e, isSkip := test.err.(skipError); isSkip {
			test.err = nil
			errStr = "unexpected skip for " + path.Join(test.dir, test.gofile) + ": " + string(e)
			status = "FAIL"
		}
		if test.err != nil {
			status = "FAIL"
			errStr = test.err.Error()
		}
		if status == "FAIL" {
			failed = true
		}
		resCount[status]++
		dt := fmt.Sprintf("%.3fs", test.dt.Seconds())
		if status == "FAIL" {
			fmt.Printf("# go run run.go -- %s\n%s\nFAIL\t%s\t%s\n",
				path.Join(test.dir, test.gofile),
				errStr, test.goFileName(), dt)
			continue
		}
		if !*verbose {
			continue
		}
		fmt.Printf("%s\t%s\t%s\n", status, test.goFileName(), dt)
	}

	if *summary {
		for k, v := range resCount {
			fmt.Printf("%5d %s\n", v, k)
		}
	}

	if failed {
		os.Exit(1)
	}
}

func toolPath(name string) string {
	p := filepath.Join(os.Getenv("GOROOT"), "bin", "tool", name)
	if _, err := os.Stat(p); err != nil {
		log.Fatalf("didn't find binary at %s", p)
	}
	return p
}

func shardMatch(name string) bool {
	if *shards == 0 {
		return true
	}
	h := fnv.New32()
	io.WriteString(h, name)
	return int(h.Sum32()%uint32(*shards)) == *shard
}

func goFiles(dir string) []string {
	f, err := os.Open(dir)
	check(err)
	dirnames, err := f.Readdirnames(-1)
	check(err)
	names := []string{}
	for _, name := range dirnames {
		if !strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".go") && shardMatch(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

type runCmd func(...string) ([]byte, error)

func compileFile(runcmd runCmd, longname string, flags []string) (out []byte, err error) {
	cmd := []string{"go", "tool", "compile", "-e"}
	cmd = append(cmd, flags...)
	if *linkshared {
		cmd = append(cmd, "-dynlink", "-installsuffix=dynlink")
	}
	cmd = append(cmd, longname)
	return runcmd(cmd...)
}

func compileInDir(runcmd runCmd, dir string, flags []string, names ...string) (out []byte, err error) {
	cmd := []string{"go", "tool", "compile", "-e", "-D", ".", "-I", "."}
	cmd = append(cmd, flags...)
	if *linkshared {
		cmd = append(cmd, "-dynlink", "-installsuffix=dynlink")
	}
	for _, name := range names {
		cmd = append(cmd, filepath.Join(dir, name))
	}
	return runcmd(cmd...)
}

func linkFile(runcmd runCmd, goname string) (err error) {
	pfile := strings.Replace(goname, ".go", ".o", -1)
	cmd := []string{"go", "tool", "link", "-w", "-o", "a.exe", "-L", "."}
	if *linkshared {
		cmd = append(cmd, "-linkshared", "-installsuffix=dynlink")
	}
	cmd = append(cmd, pfile)
	_, err = runcmd(cmd...)
	return
}

// skipError describes why a test was skipped.
type skipError string

func (s skipError) Error() string { return string(s) }

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// test holds the state of a test.
type test struct {
	dir, gofile string
	donec       chan bool // closed when done
	dt          time.Duration

	src string

	tempDir string
	err     error
}

// startTest
func startTest(dir, gofile string) *test {
	t := &test{
		dir:    dir,
		gofile: gofile,
		donec:  make(chan bool, 1),
	}
	if toRun == nil {
		toRun = make(chan *test, maxTests)
		go runTests()
	}
	select {
	case toRun <- t:
	default:
		panic("toRun buffer size (maxTests) is too small")
	}
	return t
}

// runTests runs tests in parallel, but respecting the order they
// were enqueued on the toRun channel.
func runTests() {
	for {
		ratec <- true
		t := <-toRun
		go func() {
			t.run()
			<-ratec
		}()
	}
}

var cwd, _ = os.Getwd()

func (t *test) goFileName() string {
	return filepath.Join(t.dir, t.gofile)
}

func (t *test) goDirName() string {
	return filepath.Join(t.dir, strings.Replace(t.gofile, ".go", ".dir", -1))
}

func goDirFiles(longdir string) (filter []os.FileInfo, err error) {
	files, dirErr := ioutil.ReadDir(longdir)
	if dirErr != nil {
		return nil, dirErr
	}
	for _, gofile := range files {
		if filepath.Ext(gofile.Name()) == ".go" {
			filter = append(filter, gofile)
		}
	}
	return
}

var packageRE = regexp.MustCompile(`(?m)^package (\w+)`)

// If singlefilepkgs is set, each file is considered a separate package
// even if the package names are the same.
func goDirPackages(longdir string, singlefilepkgs bool) ([][]string, error) {
	files, err := goDirFiles(longdir)
	if err != nil {
		return nil, err
	}
	var pkgs [][]string
	m := make(map[string]int)
	for _, file := range files {
		name := file.Name()
		data, err := ioutil.ReadFile(filepath.Join(longdir, name))
		if err != nil {
			return nil, err
		}
		pkgname := packageRE.FindStringSubmatch(string(data))
		if pkgname == nil {
			return nil, fmt.Errorf("cannot find package name in %s", name)
		}
		i, ok := m[pkgname[1]]
		if singlefilepkgs || !ok {
			i = len(pkgs)
			pkgs = append(pkgs, nil)
			m[pkgname[1]] = i
		}
		pkgs[i] = append(pkgs[i], name)
	}
	return pkgs, nil
}

type context struct {
	GOOS   string
	GOARCH string
}

// shouldTest looks for build tags in a source file and returns
// whether the file should be used according to the tags.
func shouldTest(src string, goos, goarch string) (ok bool, whyNot string) {
	if *runSkips {
		return true, ""
	}
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//") {
			line = line[2:]
		} else {
			continue
		}
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] != '+' {
			continue
		}
		ctxt := &context{
			GOOS:   goos,
			GOARCH: goarch,
		}
		words := strings.Fields(line)
		if words[0] == "+build" {
			ok := false
			for _, word := range words[1:] {
				if ctxt.match(word) {
					ok = true
					break
				}
			}
			if !ok {
				// no matching tag found.
				return false, line
			}
		}
	}
	// no build tags
	return true, ""
}

func (ctxt *context) match(name string) bool {
	if name == "" {
		return false
	}
	if i := strings.Index(name, ","); i >= 0 {
		// comma-separated list
		return ctxt.match(name[:i]) && ctxt.match(name[i+1:])
	}
	if strings.HasPrefix(name, "!!") { // bad syntax, reject always
		return false
	}
	if strings.HasPrefix(name, "!") { // negation
		return len(name) > 1 && !ctxt.match(name[1:])
	}

	// Tags must be letters, digits, underscores or dots.
	// Unlike in Go identifiers, all digits are fine (e.g., "386").
	for _, c := range name {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '_' && c != '.' {
			return false
		}
	}

	if name == ctxt.GOOS || name == ctxt.GOARCH {
		return true
	}

	if name == "test_run" {
		return true
	}

	return false
}

func init() { checkShouldTest() }

// goGcflags returns the -gcflags argument to use with go build / go run.
// This must match the flags used for building the standard libary,
// or else the commands will rebuild any needed packages (like runtime)
// over and over.
func goGcflags() string {
	return "-gcflags=" + os.Getenv("GO_GCFLAGS")
}

// run runs a test.
func (t *test) run() {
	start := time.Now()
	defer func() {
		t.dt = time.Since(start)
		close(t.donec)
	}()

	srcBytes, err := ioutil.ReadFile(t.goFileName())
	if err != nil {
		t.err = err
		return
	}
	t.src = string(srcBytes)
	if t.src[0] == '\n' {
		t.err = skipError("starts with newline")
		return
	}

	// Execution recipe stops at first blank line.
	pos := strings.Index(t.src, "\n\n")
	if pos == -1 {
		t.err = errors.New("double newline not found")
		return
	}
	action := t.src[:pos]
	if nl := strings.Index(action, "\n"); nl >= 0 && strings.Contains(action[:nl], "+build") {
		// skip first line
		action = action[nl+1:]
	}
	if strings.HasPrefix(action, "//") {
		action = action[2:]
	}

	// Check for build constraints only up to the actual code.
	pkgPos := strings.Index(t.src, "\npackage")
	if pkgPos == -1 {
		pkgPos = pos // some files are intentionally malformed
	}
	if ok, why := shouldTest(t.src[:pkgPos], goos, goarch); !ok {
		if *showSkips {
			fmt.Printf("%-20s %-20s: %s\n", "skip", t.goFileName(), why)
		}
		return
	}

	var args, flags []string
	var tim int
	wantError := false
	wantAuto := false
	singlefilepkgs := false
	f := strings.Fields(action)
	if len(f) > 0 {
		action = f[0]
		args = f[1:]
	}

	// TODO: Clean up/simplify this switch statement.
	switch action {
	case "rundircmpout":
		action = "rundir"
	case "cmpout":
		action = "run" // the run case already looks for <dir>/<test>.out files
	case "compile", "compiledir", "build", "builddir", "run", "buildrun", "runoutput", "rundir":
		// nothing to do
	case "errorcheckandrundir":
		wantError = false // should be no error if also will run
	case "errorcheckwithauto":
		action = "errorcheck"
		wantAuto = true
		wantError = true
	case "errorcheck", "errorcheckdir", "errorcheckoutput":
		wantError = true
	case "skip":
		if *runSkips {
			break
		}
		return
	default:
		t.err = skipError("skipped; unknown pattern: " + action)
		return
	}

	// collect flags
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-0":
			wantError = false
		case "-s":
			singlefilepkgs = true
		case "-t": // timeout in seconds
			args = args[1:]
			var err error
			tim, err = strconv.Atoi(args[0])
			if err != nil {
				t.err = fmt.Errorf("need number of seconds for -t timeout, got %s instead", args[0])
			}

		default:
			flags = append(flags, args[0])
		}
		args = args[1:]
	}

	t.makeTempDir()
	if !*keep {
		defer os.RemoveAll(t.tempDir)
	}

	err = ioutil.WriteFile(filepath.Join(t.tempDir, t.gofile), srcBytes, 0644)
	check(err)

	// A few tests (of things like the environment) require these to be set.
	if os.Getenv("GOOS") == "" {
		os.Setenv("GOOS", runtime.GOOS)
	}
	if os.Getenv("GOARCH") == "" {
		os.Setenv("GOARCH", runtime.GOARCH)
	}

	useTmp := true
	runcmd := func(args ...string) ([]byte, error) {
		cmd := exec.Command(args[0], args[1:]...)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		if useTmp {
			cmd.Dir = t.tempDir
			cmd.Env = envForDir(cmd.Dir)
		} else {
			cmd.Env = os.Environ()
		}

		var err error

		if tim != 0 {
			err = cmd.Start()
			// This command-timeout code adapted from cmd/go/test.go
			if err == nil {
				tick := time.NewTimer(time.Duration(tim) * time.Second)
				done := make(chan error)
				go func() {
					done <- cmd.Wait()
				}()
				select {
				case err = <-done:
					// ok
				case <-tick.C:
					cmd.Process.Kill()
					err = <-done
					// err = errors.New("Test timeout")
				}
				tick.Stop()
			}
		} else {
			err = cmd.Run()
		}
		if err != nil {
			err = fmt.Errorf("%s\n%s", err, buf.Bytes())
		}
		return buf.Bytes(), err
	}

	long := filepath.Join(cwd, t.goFileName())
	switch action {
	default:
		t.err = fmt.Errorf("unimplemented action %q", action)

	case "errorcheck":
		// TODO(gri) remove need for -C (disable printing of columns in error messages)
		cmdline := []string{"go", "tool", "compile", "-C", "-e", "-o", "a.o"}
		// No need to add -dynlink even if linkshared if we're just checking for errors...
		cmdline = append(cmdline, flags...)
		cmdline = append(cmdline, long)
		out, err := runcmd(cmdline...)
		if wantError {
			if err == nil {
				t.err = fmt.Errorf("compilation succeeded unexpectedly\n%s", out)
				return
			}
		} else {
			if err != nil {
				t.err = err
				return
			}
		}
		if *updateErrors {
			t.updateErrors(string(out), long)
		}
		t.err = t.errorCheck(string(out), wantAuto, long, t.gofile)
		return

	case "compile":
		_, t.err = compileFile(runcmd, long, flags)

	case "compiledir":
		// Compile all files in the directory in lexicographic order.
		longdir := filepath.Join(cwd, t.goDirName())
		pkgs, err := goDirPackages(longdir, singlefilepkgs)
		if err != nil {
			t.err = err
			return
		}
		for _, gofiles := range pkgs {
			_, t.err = compileInDir(runcmd, longdir, flags, gofiles...)
			if t.err != nil {
				return
			}
		}

	case "errorcheckdir", "errorcheckandrundir":
		// errorcheck all files in lexicographic order
		// useful for finding importing errors
		longdir := filepath.Join(cwd, t.goDirName())
		pkgs, err := goDirPackages(longdir, singlefilepkgs)
		if err != nil {
			t.err = err
			return
		}
		for i, gofiles := range pkgs {
			out, err := compileInDir(runcmd, longdir, flags, gofiles...)
			if i == len(pkgs)-1 {
				if wantError && err == nil {
					t.err = fmt.Errorf("compilation succeeded unexpectedly\n%s", out)
					return
				} else if !wantError && err != nil {
					t.err = err
					return
				}
			} else if err != nil {
				t.err = err
				return
			}
			var fullshort []string
			for _, name := range gofiles {
				fullshort = append(fullshort, filepath.Join(longdir, name), name)
			}
			t.err = t.errorCheck(string(out), wantAuto, fullshort...)
			if t.err != nil {
				break
			}
		}
		if action == "errorcheckdir" {
			return
		}
		fallthrough

	case "rundir":
		// Compile all files in the directory in lexicographic order.
		// then link as if the last file is the main package and run it
		longdir := filepath.Join(cwd, t.goDirName())
		pkgs, err := goDirPackages(longdir, singlefilepkgs)
		if err != nil {
			t.err = err
			return
		}
		for i, gofiles := range pkgs {
			_, err := compileInDir(runcmd, longdir, flags, gofiles...)
			if err != nil {
				t.err = err
				return
			}
			if i == len(pkgs)-1 {
				err = linkFile(runcmd, gofiles[0])
				if err != nil {
					t.err = err
					return
				}
				var cmd []string
				cmd = append(cmd, findExecCmd()...)
				cmd = append(cmd, filepath.Join(t.tempDir, "a.exe"))
				cmd = append(cmd, args...)
				out, err := runcmd(cmd...)
				if err != nil {
					t.err = err
					return
				}
				if strings.Replace(string(out), "\r\n", "\n", -1) != t.expectedOutput() {
					t.err = fmt.Errorf("incorrect output\n%s", out)
				}
			}
		}

	case "build":
		_, err := runcmd("go", "build", goGcflags(), "-o", "a.exe", long)
		if err != nil {
			t.err = err
		}

	case "builddir":
		// Build an executable from all the .go and .s files in a subdirectory.
		useTmp = true
		longdir := filepath.Join(cwd, t.goDirName())
		files, dirErr := ioutil.ReadDir(longdir)
		if dirErr != nil {
			t.err = dirErr
			break
		}
		var gos []os.FileInfo
		var asms []os.FileInfo
		for _, file := range files {
			switch filepath.Ext(file.Name()) {
			case ".go":
				gos = append(gos, file)
			case ".s":
				asms = append(asms, file)
			}

		}
		var objs []string
		cmd := []string{"go", "tool", "compile", "-e", "-D", ".", "-I", ".", "-o", "go.o"}
		if len(asms) > 0 {
			cmd = append(cmd, "-asmhdr", "go_asm.h")
		}
		for _, file := range gos {
			cmd = append(cmd, filepath.Join(longdir, file.Name()))
		}
		_, err := runcmd(cmd...)
		if err != nil {
			t.err = err
			break
		}
		objs = append(objs, "go.o")
		if len(asms) > 0 {
			cmd = []string{"go", "tool", "asm", "-e", "-I", ".", "-o", "asm.o"}
			for _, file := range asms {
				cmd = append(cmd, filepath.Join(longdir, file.Name()))
			}
			_, err = runcmd(cmd...)
			if err != nil {
				t.err = err
				break
			}
			objs = append(objs, "asm.o")
		}
		cmd = []string{"go", "tool", "pack", "c", "all.a"}
		cmd = append(cmd, objs...)
		_, err = runcmd(cmd...)
		if err != nil {
			t.err = err
			break
		}
		cmd = []string{"go", "tool", "link", "all.a"}
		_, err = runcmd(cmd...)
		if err != nil {
			t.err = err
			break
		}

	case "buildrun": // build binary, then run binary, instead of go run. Useful for timeout tests where failure mode is infinite loop.
		// TODO: not supported on NaCl
		useTmp = true
		cmd := []string{"go", "build", goGcflags(), "-o", "a.exe"}
		if *linkshared {
			cmd = append(cmd, "-linkshared")
		}
		longdirgofile := filepath.Join(filepath.Join(cwd, t.dir), t.gofile)
		cmd = append(cmd, flags...)
		cmd = append(cmd, longdirgofile)
		out, err := runcmd(cmd...)
		if err != nil {
			t.err = err
			return
		}
		cmd = []string{"./a.exe"}
		out, err = runcmd(append(cmd, args...)...)
		if err != nil {
			t.err = err
			return
		}

		if strings.Replace(string(out), "\r\n", "\n", -1) != t.expectedOutput() {
			t.err = fmt.Errorf("incorrect output\n%s", out)
		}

	case "run":
		useTmp = false
		var out []byte
		var err error
		if len(flags)+len(args) == 0 && goGcflags() == "" && !*linkshared {
			// If we're not using special go command flags,
			// skip all the go command machinery.
			// This avoids any time the go command would
			// spend checking whether, for example, the installed
			// package runtime is up to date.
			// Because we run lots of trivial test programs,
			// the time adds up.
			pkg := filepath.Join(t.tempDir, "pkg.a")
			if _, err := runcmd("go", "tool", "compile", "-o", pkg, t.goFileName()); err != nil {
				t.err = err
				return
			}
			exe := filepath.Join(t.tempDir, "test.exe")
			cmd := []string{"go", "tool", "link", "-s", "-w"}
			cmd = append(cmd, "-o", exe, pkg)
			if _, err := runcmd(cmd...); err != nil {
				t.err = err
				return
			}
			out, err = runcmd(append([]string{exe}, args...)...)
		} else {
			cmd := []string{"go", "run", goGcflags()}
			if *linkshared {
				cmd = append(cmd, "-linkshared")
			}
			cmd = append(cmd, flags...)
			cmd = append(cmd, t.goFileName())
			out, err = runcmd(append(cmd, args...)...)
		}
		if err != nil {
			t.err = err
			return
		}
		if strings.Replace(string(out), "\r\n", "\n", -1) != t.expectedOutput() {
			t.err = fmt.Errorf("incorrect output\n%s", out)
		}

	case "runoutput":
		rungatec <- true
		defer func() {
			<-rungatec
		}()
		useTmp = false
		cmd := []string{"go", "run", goGcflags()}
		if *linkshared {
			cmd = append(cmd, "-linkshared")
		}
		cmd = append(cmd, t.goFileName())
		out, err := runcmd(append(cmd, args...)...)
		if err != nil {
			t.err = err
			return
		}
		tfile := filepath.Join(t.tempDir, "tmp__.go")
		if err := ioutil.WriteFile(tfile, out, 0666); err != nil {
			t.err = fmt.Errorf("write tempfile:%s", err)
			return
		}
		cmd = []string{"go", "run", goGcflags()}
		if *linkshared {
			cmd = append(cmd, "-linkshared")
		}
		cmd = append(cmd, tfile)
		out, err = runcmd(cmd...)
		if err != nil {
			t.err = err
			return
		}
		if string(out) != t.expectedOutput() {
			t.err = fmt.Errorf("incorrect output\n%s", out)
		}

	case "errorcheckoutput":
		useTmp = false
		cmd := []string{"go", "run", goGcflags()}
		if *linkshared {
			cmd = append(cmd, "-linkshared")
		}
		cmd = append(cmd, t.goFileName())
		out, err := runcmd(append(cmd, args...)...)
		if err != nil {
			t.err = err
			return
		}
		tfile := filepath.Join(t.tempDir, "tmp__.go")
		err = ioutil.WriteFile(tfile, out, 0666)
		if err != nil {
			t.err = fmt.Errorf("write tempfile:%s", err)
			return
		}
		cmdline := []string{"go", "tool", "compile", "-e", "-o", "a.o"}
		cmdline = append(cmdline, flags...)
		cmdline = append(cmdline, tfile)
		out, err = runcmd(cmdline...)
		if wantError {
			if err == nil {
				t.err = fmt.Errorf("compilation succeeded unexpectedly\n%s", out)
				return
			}
		} else {
			if err != nil {
				t.err = err
				return
			}
		}
		t.err = t.errorCheck(string(out), false, tfile, "tmp__.go")
		return
	}
}

var execCmd []string

func findExecCmd() []string {
	if execCmd != nil {
		return execCmd
	}
	execCmd = []string{} // avoid work the second time
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		return execCmd
	}
	path, err := exec.LookPath(fmt.Sprintf("go_%s_%s_exec", goos, goarch))
	if err == nil {
		execCmd = []string{path}
	}
	return execCmd
}

func (t *test) String() string {
	return filepath.Join(t.dir, t.gofile)
}

func (t *test) makeTempDir() {
	var err error
	t.tempDir, err = ioutil.TempDir("", "")
	check(err)
	if *keep {
		log.Printf("Temporary directory is %s", t.tempDir)
	}
}

func (t *test) expectedOutput() string {
	filename := filepath.Join(t.dir, t.gofile)
	filename = filename[:len(filename)-len(".go")]
	filename += ".out"
	b, _ := ioutil.ReadFile(filename)
	return string(b)
}

func splitOutput(out string, wantAuto bool) []string {
	// gc error messages continue onto additional lines with leading tabs.
	// Split the output at the beginning of each line that doesn't begin with a tab.
	// <autogenerated> lines are impossible to match so those are filtered out.
	var res []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasSuffix(line, "\r") { // remove '\r', output by compiler on windows
			line = line[:len(line)-1]
		}
		if strings.HasPrefix(line, "\t") {
			res[len(res)-1] += "\n" + line
		} else if strings.HasPrefix(line, "go tool") || strings.HasPrefix(line, "#") || !wantAuto && strings.HasPrefix(line, "<autogenerated>") {
			continue
		} else if strings.TrimSpace(line) != "" {
			res = append(res, line)
		}
	}
	return res
}

func (t *test) errorCheck(outStr string, wantAuto bool, fullshort ...string) (err error) {
	defer func() {
		if *verbose && err != nil {
			log.Printf("%s gc output:\n%s", t, outStr)
		}
	}()
	var errs []error
	out := splitOutput(outStr, wantAuto)

	// Cut directory name.
	for i := range out {
		for j := 0; j < len(fullshort); j += 2 {
			full, short := fullshort[j], fullshort[j+1]
			out[i] = strings.Replace(out[i], full, short, -1)
		}
	}

	var want []wantedError
	for j := 0; j < len(fullshort); j += 2 {
		full, short := fullshort[j], fullshort[j+1]
		want = append(want, t.wantedErrors(full, short)...)
	}

	for _, we := range want {
		var errmsgs []string
		if we.auto {
			errmsgs, out = partitionStrings("<autogenerated>", out)
		} else {
			errmsgs, out = partitionStrings(we.prefix, out)
		}
		if len(errmsgs) == 0 {
			errs = append(errs, fmt.Errorf("%s:%d: missing error %q", we.file, we.lineNum, we.reStr))
			continue
		}
		matched := false
		n := len(out)
		for _, errmsg := range errmsgs {
			// Assume errmsg says "file:line: foo".
			// Cut leading "file:line: " to avoid accidental matching of file name instead of message.
			text := errmsg
			if i := strings.Index(text, " "); i >= 0 {
				text = text[i+1:]
			}
			if we.re.MatchString(text) {
				matched = true
			} else {
				out = append(out, errmsg)
			}
		}
		if !matched {
			errs = append(errs, fmt.Errorf("%s:%d: no match for %#q in:\n\t%s", we.file, we.lineNum, we.reStr, strings.Join(out[n:], "\n\t")))
			continue
		}
	}

	if len(out) > 0 {
		errs = append(errs, fmt.Errorf("Unmatched Errors:"))
		for _, errLine := range out {
			errs = append(errs, fmt.Errorf("%s", errLine))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "\n")
	for _, err := range errs {
		fmt.Fprintf(&buf, "%s\n", err.Error())
	}
	return errors.New(buf.String())
}

func (t *test) updateErrors(out, file string) {
	base := path.Base(file)
	// Read in source file.
	src, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	lines := strings.Split(string(src), "\n")
	// Remove old errors.
	for i, ln := range lines {
		pos := strings.Index(ln, " // ERROR ")
		if pos >= 0 {
			lines[i] = ln[:pos]
		}
	}
	// Parse new errors.
	errors := make(map[int]map[string]bool)
	tmpRe := regexp.MustCompile(`autotmp_[0-9]+`)
	for _, errStr := range splitOutput(out, false) {
		colon1 := strings.Index(errStr, ":")
		if colon1 < 0 || errStr[:colon1] != file {
			continue
		}
		colon2 := strings.Index(errStr[colon1+1:], ":")
		if colon2 < 0 {
			continue
		}
		colon2 += colon1 + 1
		line, err := strconv.Atoi(errStr[colon1+1 : colon2])
		line--
		if err != nil || line < 0 || line >= len(lines) {
			continue
		}
		msg := errStr[colon2+2:]
		msg = strings.Replace(msg, file, base, -1) // normalize file mentions in error itself
		msg = strings.TrimLeft(msg, " \t")
		for _, r := range []string{`\`, `*`, `+`, `[`, `]`, `(`, `)`} {
			msg = strings.Replace(msg, r, `\`+r, -1)
		}
		msg = strings.Replace(msg, `"`, `.`, -1)
		msg = tmpRe.ReplaceAllLiteralString(msg, `autotmp_[0-9]+`)
		if errors[line] == nil {
			errors[line] = make(map[string]bool)
		}
		errors[line][msg] = true
	}
	// Add new errors.
	for line, errs := range errors {
		var sorted []string
		for e := range errs {
			sorted = append(sorted, e)
		}
		sort.Strings(sorted)
		lines[line] += " // ERROR"
		for _, e := range sorted {
			lines[line] += fmt.Sprintf(` "%s$"`, e)
		}
	}
	// Write new file.
	err = ioutil.WriteFile(file, []byte(strings.Join(lines, "\n")), 0640)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	// Polish.
	exec.Command("go", "fmt", file).CombinedOutput()
}

// matchPrefix reports whether s is of the form ^(.*/)?prefix(:|[),
// That is, it needs the file name prefix followed by a : or a [,
// and possibly preceded by a directory name.
func matchPrefix(s, prefix string) bool {
	i := strings.Index(s, ":")
	if i < 0 {
		return false
	}
	j := strings.LastIndex(s[:i], "/")
	s = s[j+1:]
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		return false
	}
	switch s[len(prefix)] {
	case '[', ':':
		return true
	}
	return false
}

func partitionStrings(prefix string, strs []string) (matched, unmatched []string) {
	for _, s := range strs {
		if matchPrefix(s, prefix) {
			matched = append(matched, s)
		} else {
			unmatched = append(unmatched, s)
		}
	}
	return
}

type wantedError struct {
	reStr   string
	re      *regexp.Regexp
	lineNum int
	auto    bool // match <autogenerated> line
	file    string
	prefix  string
}

var (
	errRx       = regexp.MustCompile(`// (?:GC_)?ERROR (.*)`)
	errAutoRx   = regexp.MustCompile(`// (?:GC_)?ERRORAUTO (.*)`)
	errQuotesRx = regexp.MustCompile(`"([^"]*)"`)
	lineRx      = regexp.MustCompile(`LINE(([+-])([0-9]+))?`)
)

func (t *test) wantedErrors(file, short string) (errs []wantedError) {
	cache := make(map[string]*regexp.Regexp)

	src, _ := ioutil.ReadFile(file)
	for i, line := range strings.Split(string(src), "\n") {
		lineNum := i + 1
		if strings.Contains(line, "////") {
			// double comment disables ERROR
			continue
		}
		var auto bool
		m := errAutoRx.FindStringSubmatch(line)
		if m != nil {
			auto = true
		} else {
			m = errRx.FindStringSubmatch(line)
		}
		if m == nil {
			continue
		}
		all := m[1]
		mm := errQuotesRx.FindAllStringSubmatch(all, -1)
		if mm == nil {
			log.Fatalf("%s:%d: invalid errchk line: %s", t.goFileName(), lineNum, line)
		}
		for _, m := range mm {
			rx := lineRx.ReplaceAllStringFunc(m[1], func(m string) string {
				n := lineNum
				if strings.HasPrefix(m, "LINE+") {
					delta, _ := strconv.Atoi(m[5:])
					n += delta
				} else if strings.HasPrefix(m, "LINE-") {
					delta, _ := strconv.Atoi(m[5:])
					n -= delta
				}
				return fmt.Sprintf("%s:%d", short, n)
			})
			re := cache[rx]
			if re == nil {
				var err error
				re, err = regexp.Compile(rx)
				if err != nil {
					log.Fatalf("%s:%d: invalid regexp \"%s\" in ERROR line: %v", t.goFileName(), lineNum, rx, err)
				}
				cache[rx] = re
			}
			prefix := fmt.Sprintf("%s:%d", short, lineNum)
			errs = append(errs, wantedError{
				reStr:   rx,
				re:      re,
				prefix:  prefix,
				auto:    auto,
				lineNum: lineNum,
				file:    short,
			})
		}
	}

	return
}

// defaultRunOutputLimit returns the number of runoutput tests that
// can be executed in parallel.
func defaultRunOutputLimit() int {
	const maxArmCPU = 2

	cpu := runtime.NumCPU()
	if runtime.GOARCH == "arm" && cpu > maxArmCPU {
		cpu = maxArmCPU
	}
	return cpu
}

// checkShouldTest runs sanity checks on the shouldTest function.
func checkShouldTest() {
	assert := func(ok bool, _ string) {
		if !ok {
			panic("fail")
		}
	}
	assertNot := func(ok bool, _ string) { assert(!ok, "") }

	// Simple tests.
	assert(shouldTest("// +build linux", "linux", "arm"))
	assert(shouldTest("// +build !windows", "linux", "arm"))
	assertNot(shouldTest("// +build !windows", "windows", "amd64"))

	// A file with no build tags will always be tested.
	assert(shouldTest("// This is a test.", "os", "arch"))

	// Build tags separated by a space are OR-ed together.
	assertNot(shouldTest("// +build arm 386", "linux", "amd64"))

	// Build tags separated by a comma are AND-ed together.
	assertNot(shouldTest("// +build !windows,!plan9", "windows", "amd64"))
	assertNot(shouldTest("// +build !windows,!plan9", "plan9", "386"))

	// Build tags on multiple lines are AND-ed together.
	assert(shouldTest("// +build !windows\n// +build amd64", "linux", "amd64"))
	assertNot(shouldTest("// +build !windows\n// +build amd64", "windows", "amd64"))

	// Test that (!a OR !b) matches anything.
	assert(shouldTest("// +build !windows !plan9", "windows", "amd64"))
}

// envForDir returns a copy of the environment
// suitable for running in the given directory.
// The environment is the current process's environment
// but with an updated $PWD, so that an os.Getwd in the
// child will be faster.
func envForDir(dir string) []string {
	env := os.Environ()
	for i, kv := range env {
		if strings.HasPrefix(kv, "PWD=") {
			env[i] = "PWD=" + dir
			return env
		}
	}
	env = append(env, "PWD="+dir)
	return env
}

func getenv(key, def string) string {
	value := os.Getenv(key)
	if value != "" {
		return value
	}
	return def
}
