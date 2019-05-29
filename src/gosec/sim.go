package gosec

/* This file implements a simulated environnement to load and execute enclave
 * binaries without sgx.
 */

import (
	"debug/elf"
	"fmt"
	"log"
	"runtime"
	"sort"
	"syscall"
	"unsafe"
)

func simLoadProgram(path string) {
	fmt.Println("[DEBUG] loading the program in simulation.")
	file, err := elf.Open(path)
	check(err)
	_, enclWrap = sgxCreateSecs(file)
	enclWrap.isSim = true
	srcWrap = transposeOutWrapper(enclWrap)
	defer func() { check(file.Close()) }()

	// Check that the sections are sorted now.
	sort.Sort(SortedElfSections(file.Sections))

	var aggreg []*elf.Section
	for _, sec := range file.Sections {
		if sec.Flags&elf.SHF_ALLOC != elf.SHF_ALLOC {
			continue
		}
		if len(aggreg) == 0 || aggreg[len(aggreg)-1].Flags == sec.Flags {
			aggreg = append(aggreg, sec)
			continue
		}
		mapSections(aggreg)
		aggreg = nil
		aggreg = append(aggreg, sec)
	}
	mapSections(aggreg)

	//For debugging.
	enclWrap.DumpDebugInfo()
	// Map the enclave preallocated heap.
	simPreallocate(enclWrap)

	for _, tcs := range enclWrap.tcss {
		prot := _PROT_READ | _PROT_WRITE
		manon := _MAP_PRIVATE | _MAP_ANON | _MAP_FIXED
		// mmap the stack
		_, err = syscall.RMmap(tcs.Stack, int(tcs.Ssiz), prot, manon, -1, 0)
		check(err)
	}

	// register the heap, setup the enclave stack
	etcs := enclWrap.defaultTcs()
	etcs.Used = true
	srcWrap.defaultTcs().Used = true
	runtime.Cooprt.Tcss = enclWrap.tcss
	_ = runtime.SetupEnclSysStack(etcs.Stack+etcs.Ssiz, enclWrap.mhstart)

	// Create the thread for enclave, setups the stacks.
	fn := unsafe.Pointer(uintptr(file.Entry))
	enclWrap.entry = uintptr(fn)
	dtcs, stcs := enclWrap.defaultTcs(), srcWrap.defaultTcs()
	dtcs.Used, stcs.Used = true, true
	sgxEEnter(uint64(0), dtcs, stcs, nil)
}

func simPreallocate(wrap *sgx_wrapper) {
	prot := _PROT_READ | _PROT_WRITE
	flags := _MAP_ANON | _MAP_FIXED | _MAP_PRIVATE

	// The span
	_, err := syscall.RMmap(wrap.mhstart, int(wrap.mhsize), prot,
		flags, -1, 0)
	check(err)

	// The memory buffer for mmap calls.
	_, err = syscall.RMmap(wrap.membuf, int(MEMBUF_SIZE), prot,
		flags, -1, 0)
	check(err)
}

// mapSections mmaps the elf sections.
// If wrap nil, simple mmap. Otherwise, mmap to another address space specified
// by wrap.mmask for SGX.
func mapSections(secs []*elf.Section) {
	if len(secs) == 0 {
		return
	}

	start := uintptr(secs[0].Addr)
	end := uintptr(secs[len(secs)-1].Addr + secs[len(secs)-1].Size)
	size := int(end - start)
	if start >= end {
		log.Fatalf("Error, sections are not ordered: %#x - %#x", start, end)
	}

	prot := _PROT_READ | _PROT_WRITE
	b, err := syscall.RMmap(start, size, prot, _MAP_PRIVATE|_MAP_ANON, -1, 0)
	check(err)

	for _, sec := range secs {
		if sec.Type == elf.SHT_NOBITS {
			continue
		}
		data, err := sec.Data()
		check(err)
		offset := int(sec.Addr - uint64(start))
		for i := range data {
			b[offset+i] = data[i]
		}
	}
	prot = _PROT_READ
	if (secs[0].Flags & elf.SHF_WRITE) == elf.SHF_WRITE {
		prot |= _PROT_WRITE
	}

	if (secs[0].Flags & elf.SHF_EXECINSTR) == elf.SHF_EXECINSTR {
		prot |= _PROT_EXEC
	}

	err = syscall.Mprotect(b, prot)
	check(err)
}
