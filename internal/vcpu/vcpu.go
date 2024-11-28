package vcpu

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
	sys "golang.org/x/sys/unix"
)

// Exact kernel structure matches
type KVMSegment struct {
	Base     uint64
	Limit    uint32
	Selector uint16
	Type     uint8
	Present  uint8
	DPL      uint8
	DB       uint8
	S        uint8
	L        uint8
	G        uint8
	AVL      uint8
	Unusable uint8
	Padding  uint8
}

type KVMDTable struct {
	Base    uint64
	Limit   uint16
	Padding [3]uint16
}

type KVMSRegs struct {
	CS               KVMSegment
	DS               KVMSegment
	ES               KVMSegment
	FS               KVMSegment
	GS               KVMSegment
	SS               KVMSegment
	TR               KVMSegment
	LDT              KVMSegment
	GDT              KVMDTable
	IDT              KVMDTable
	CR0              uint64
	CR2              uint64
	CR3              uint64
	CR4              uint64
	CR8              uint64
	EFER             uint64
	APIC_BASE        uint64
	INTERRUPT_BITMAP [3]uint64
}

type KVMRegs struct {
	RAX    uint64
	RBX    uint64
	RCX    uint64
	RDX    uint64
	RSI    uint64
	RDI    uint64
	RSP    uint64
	RBP    uint64
	R8     uint64
	R9     uint64
	R10    uint64
	R11    uint64
	R12    uint64
	R13    uint64
	R14    uint64
	R15    uint64
	RIP    uint64
	RFLAGS uint64
}

type KVMFailEntry struct {
	HardwareEntryFailureReason uint64
	CPU                        uint32
	_                          [4]uint8
}

// KVMRun represents the shared structure between KVM and userspace
type KVMRun struct {
	RequestInterruptWindow     uint8
	ImmediateExit              uint8
	Padding1                   [6]uint8
	ExitReason                 uint32
	ReadyForInterruptInjection uint8
	IfFlag                     uint8
	Flags                      uint16
	CR8                        uint64
	ApicBase                   uint64

	// Union of exit types
	IO struct {
		Direction  uint8
		Size       uint8
		Port       uint16
		Count      uint32
		DataOffset uint64
	}
	FailEntry KVMFailEntry
}

// Constants - using exact values from the other implementation
const (
	KVM_GET_API_VERSION        = uintptr(44544)
	KVM_CREATE_VM              = uintptr(44545)
	KVM_GET_VCPU_MMAP_SIZE     = uintptr(44548)
	KVM_CREATE_VCPU            = uintptr(44609)
	KVM_RUN                    = uintptr(44672)
	KVM_SET_USER_MEMORY_REGION = uintptr(1075883590)
	KVM_GET_SREGS              = int(-2126991741)
	KVM_SET_SREGS              = uintptr(1094233732)
	KVM_SET_REGS               = uintptr(1083223682)

	// Other consts
	KVM_NR_INTERRUPTS        = 256
	KVM_EXIT_UNKNOWN         = 0
	KVM_EXIT_EXCEPTION       = 1
	KVM_EXIT_IO              = 2
	KVM_EXIT_HYPERCALL       = 3
	KVM_EXIT_DEBUG           = 4
	KVM_EXIT_HLT             = 5
	KVM_EXIT_MMIO            = 6
	KVM_EXIT_IRQ_WINDOW_OPEN = 7
	KVM_EXIT_SHUTDOWN        = 8
	KVM_EXIT_FAIL_ENTRY      = 9
	KVM_EXIT_INTR            = 10
	KVM_EXIT_SET_TPR         = 11
	KVM_EXIT_TPR_ACCESS      = 12
	KVM_EXIT_INTERNAL_ERROR  = 17

	SERIAL_PORT_COM1 = 0x3f8
	KERNEL_LOAD_ADDR = 0x100000 // 1MB mark

	PAGE_TABLE_BASE = 0xffff0000 // Where gokvm puts page tables
	PAGE_SIZE       = 0x1000     // 4KB
	CR4_PAE         = 0x00000020 // Physical Address Extension
	CR0_PE          = 0x00000001 // Protected mode
	CR0_MP          = 0x00000002 // Monitor co-processor
	CR0_ET          = 0x00000010 // Extension type
	CR0_NE          = 0x00000020 // Numeric error
	CR0_WP          = 0x00010000 // Write protect
	CR0_AM          = 0x00040000 // Alignment mask
	CR0_PG          = 0x80000000 // Paging
	EFER_LME        = 0x00000100 // Long mode enable
	EFER_LMA        = 0x00000400 // Long mode active
)

type VCPU struct {
	fd      int
	mmap    []byte
	vmfd    int
	id      int
	signals chan os.Signal
}

func ioctl(fd, op, arg uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
}

func mmap(addr, size, prot, flags uintptr, fd int, off uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall6(syscall.SYS_MMAP, addr, size, prot, flags, uintptr(fd), off)
}

func memcpy(dest, src, size uintptr) {
	if dest == 0 || src == 0 {
		panic("nil argument to copy")
	}
	for i := uintptr(0); i < size; i++ {
		d := (*byte)(unsafe.Pointer(dest + i))
		s := (*byte)(unsafe.Pointer(src + i))
		*d = *s
	}
}

func trickGo(a int) uintptr {
	return uintptr(a)
}

func (vcpu *VCPU) writePhysicalMemory(physAddr uint64, data []byte) error {
	// Check bounds
	if physAddr >= uint64(len(vcpu.mmap)) || int(physAddr)+len(data) > len(vcpu.mmap) {
		return fmt.Errorf("write outside mmap bounds: addr=0x%x size=%d mmap_size=%d",
			physAddr, len(data), len(vcpu.mmap))
	}

	// Copy data to mmap
	copy(vcpu.mmap[physAddr:], data)
	return nil
}

func (vcpu *VCPU) setupPageTables() error {
	fmt.Printf("Setting up page tables in mmap of size %d bytes\n", len(vcpu.mmap))
	// Calculate bases within our mmap space
	pml4_base := uint64(0x0)    // Start at beginning of mmap
	pdpt_base := uint64(0x1000) // 4KB offset
	pd_base := uint64(0x2000)   // 8KB offset
	// Verify we have enough space
	if pd_base+PAGE_SIZE > uint64(len(vcpu.mmap)) {
		return fmt.Errorf("not enough mmap space for page tables. Need %d bytes", pd_base+PAGE_SIZE)
	}
	// Zero out the page table area
	zeros := make([]byte, 0x3000) // 12KB for three pages
	if err := vcpu.writePhysicalMemory(0, zeros); err != nil {
		return fmt.Errorf("failed to zero page tables: %v", err)
	}
	fmt.Printf("Setting up PML4 at 0x%x\n", pml4_base)
	// Set up PML4 entry pointing to PDPT
	pml4e := pdpt_base | 0x3 // Present + R/W
	if err := vcpu.writePhysicalMemory(pml4_base, uint64ToBytes(pml4e)); err != nil {
		return fmt.Errorf("failed to write PML4: %v", err)
	}
	fmt.Printf("Setting up PDPT at 0x%x\n", pdpt_base)
	// Set up PDPT entry pointing to PD
	pdpte := pd_base | 0x3 // Present + R/W
	if err := vcpu.writePhysicalMemory(pdpt_base, uint64ToBytes(pdpte)); err != nil {
		return fmt.Errorf("failed to write PDPT: %v", err)
	}
	fmt.Printf("Setting up PD at 0x%x\n", pd_base)
	// Set up PD entry for 1GB page
	pde := uint64(0) | 0x83 // Present + R/W + 1GB page
	if err := vcpu.writePhysicalMemory(pd_base, uint64ToBytes(pde)); err != nil {
		return fmt.Errorf("failed to write PD: %v", err)
	}
	fmt.Printf("Page tables setup completed\n")
	return nil
}

func clearSigset(set *sys.Sigset_t) {
	*set = unix.Sigset_t{}
}

func addSignalToSet(set *sys.Sigset_t, signo syscall.Signal) {
	set.Val[signo/64] |= 1 << (uint(signo) % 64)
}

func (vcpu *VCPU) Run() error {
	run := (*KVMRun)(unsafe.Pointer(&vcpu.mmap[0]))

	for {
		ret, _, errno := ioctl(uintptr(vcpu.fd), KVM_RUN, 0)
		if errno != 0 {
			if errno == syscall.EINTR {
				fmt.Printf("KVM_RUN interrupted\n")
				continue
			}
			return fmt.Errorf("KVM_RUN failed: %v (ret=%d)", errno, ret)
		}

		// Handle normal exits
		switch run.ExitReason {
		case KVM_EXIT_HLT:
			fmt.Printf("CPU halted")
			return nil

		case KVM_EXIT_IO:
			if run.IO.Direction == 1 { // OUT
				offset := run.IO.DataOffset
				size := uint64(run.IO.Size) * uint64(run.IO.Count)
				if offset+size <= uint64(len(vcpu.mmap)) {
					data := vcpu.mmap[offset : offset+size]
					fmt.Printf("IO: port=0x%x, size=%d, data=%q\n",
						run.IO.Port, size, string(data))
				}
			}

		case KVM_EXIT_INTERNAL_ERROR:
			return fmt.Errorf("KVM internal error")

		case KVM_EXIT_SHUTDOWN:
			return nil

		default:
			return fmt.Errorf("unhandled exit reason: %d", run.ExitReason)
		}
	}
}

func (vcpu *VCPU) getCR3() (uint64, error) {
	sregs := KVMSRegs{}
	_, _, errno := ioctl(uintptr(vcpu.fd), trickGo(KVM_GET_SREGS), uintptr(unsafe.Pointer(&sregs)))
	if errno != 0 {
		return 0, fmt.Errorf("failed to get SREGS: %v", errno)
	}
	return sregs.CR3, nil
}

func (vcpu *VCPU) GetSpecialRegisters() (*KVMSRegs, error) {
	sregs := &KVMSRegs{}
	_, _, errno := ioctl(uintptr(vcpu.fd), trickGo(KVM_GET_SREGS), uintptr(unsafe.Pointer(sregs)))
	if errno != 0 {
		return nil, fmt.Errorf("failed to get SREGS: %v", errno)
	}
	return sregs, nil
}

func NewVCPU(vmfd int, id int) (*VCPU, error) {
	// First create VCPU
	vcpufd, _, errno := ioctl(uintptr(vmfd), KVM_CREATE_VCPU, 0)
	if errno != 0 {
		return nil, fmt.Errorf("failed to create VCPU: %v", errno)
	}

	// Open /dev/kvm to get mmap size, just like in their code
	kvmfd, err := syscall.Open("/dev/kvm", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		syscall.Close(int(vcpufd))
		return nil, fmt.Errorf("failed to open /dev/kvm: %v", err)
	}
	defer syscall.Close(kvmfd)

	// Get MMAP size from the KVM fd, not VM fd
	mmapSize, _, errno := ioctl(uintptr(kvmfd), KVM_GET_VCPU_MMAP_SIZE, 0)
	if errno != 0 {
		syscall.Close(int(vcpufd))
		return nil, fmt.Errorf("failed to get mmap size: %v", errno)
	}

	// Verify minimum size
	if mmapSize < 2352 { // Same check they do
		syscall.Close(int(vcpufd))
		return nil, fmt.Errorf("KVM_GET_VCPU_MMAP_SIZE unexpectedly small: %d", mmapSize)
	}

	// MMAP the VCPU region
	mem, err := syscall.Mmap(
		int(vcpufd),
		0,
		int(mmapSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED,
	)
	if err != nil {
		syscall.Close(int(vcpufd))
		return nil, fmt.Errorf("failed to mmap: %v", err)
	}

	fmt.Printf("VCPU created with fd: %d, mmap size: %d\n", vcpufd, mmapSize)

	return &VCPU{
		fd:   int(vcpufd),
		mmap: mem,
		vmfd: vmfd,
		id:   id,
	}, nil
}

func (vcpu *VCPU) setupGDT() (uint64, error) {
	// GDT entries for 64-bit mode
	gdt := []uint64{
		0x0000000000000000, // null descriptor
		0x00af9a000000ffff, // kernel code segment (64-bit)
		0x00cf92000000ffff, // kernel data segment
	}

	// Place GDT right after our page tables at 0x2000 + PAGE_SIZE
	// We used 0x0, 0x1000, and 0x2000 for page tables
	gdt_base := uint64(0x2000) + 0x100 // Leave some space after page tables

	fmt.Printf("Setting up GDT at 0x%x with %d entries\n", gdt_base, len(gdt))
	fmt.Printf("MMAP size: %d bytes\n", len(vcpu.mmap))

	// Check if we have space
	if gdt_base+uint64(len(gdt)*8) > uint64(len(vcpu.mmap)) {
		return 0, fmt.Errorf("not enough space for GDT. Need %d bytes, have %d bytes",
			gdt_base+uint64(len(gdt)*8), len(vcpu.mmap))
	}

	// Write each GDT entry
	for i, entry := range gdt {
		if err := vcpu.writePhysicalMemory(gdt_base+uint64(i*8), uint64ToBytes(entry)); err != nil {
			return 0, fmt.Errorf("failed to write GDT entry %d: %v", i, err)
		}
	}

	// Update the GDT location in InitializeRegisters
	fmt.Printf("GDT setup completed at 0x%x\n", gdt_base)
	return gdt_base, nil // Return the base address so InitializeRegisters knows where it is
}

func (vcpu *VCPU) InitializeRegisters() error {
	fmt.Printf("Setting up registers...\n")

	// Setup page tables first
	if err := vcpu.setupPageTables(); err != nil {
		return fmt.Errorf("failed to setup page tables: %v", err)
	}

	// Setup GDT
	gdtBase, err := vcpu.setupGDT()
	if err != nil {
		return fmt.Errorf("failed to setup GDT: %v", err)
	}

	// Get current SREGS
	sregs := KVMSRegs{}
	_, _, errno := ioctl(uintptr(vcpu.fd), trickGo(KVM_GET_SREGS), uintptr(unsafe.Pointer(&sregs)))
	if errno != 0 {
		return fmt.Errorf("KVM_GET_SREGS failed: %v", errno)
	}

	// Setup CR registers for long mode
	sregs.CR3 = 0x0        // Page tables at start of mmap
	sregs.CR4 = 0x20       // PAE
	sregs.CR0 = 0x80050033 // PE, MP, ET, NE, WP, AM, PG
	sregs.EFER = 0x500     // LME + LMA

	// Setup code segment for long mode
	sregs.CS = KVMSegment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 0x8, // First GDT entry after null
		Type:     11,  // Code: execute/read
		Present:  1,
		DPL:      0,
		DB:       0, // Must be 0 for 64-bit
		S:        1, // Code/data segment
		L:        1, // 64-bit mode
		G:        1, // 4KB granularity
	}

	// Setup data segments
	dataSeg := KVMSegment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 0x10, // Second GDT entry after null
		Type:     3,    // Data: read/write
		Present:  1,
		DPL:      0,
		DB:       1,
		S:        1,
		L:        0,
		G:        1,
	}

	sregs.DS = dataSeg
	sregs.ES = dataSeg
	sregs.FS = dataSeg
	sregs.GS = dataSeg
	sregs.SS = dataSeg

	// Set up GDT and IDT
	sregs.GDT.Base = gdtBase // Where we put our GDT
	sregs.GDT.Limit = 0x17   // 3 entries, 8 bytes each - 1
	sregs.IDT.Base = 0
	sregs.IDT.Limit = 0

	fmt.Printf("Setting special registers...\n")
	fmt.Printf("  CR0: 0x%x\n", sregs.CR0)
	fmt.Printf("  CR3: 0x%x\n", sregs.CR3)
	fmt.Printf("  CR4: 0x%x\n", sregs.CR4)
	fmt.Printf("  EFER: 0x%x\n", sregs.EFER)
	fmt.Printf("  GDT.Base: 0x%x, GDT.Limit: 0x%x\n", sregs.GDT.Base, sregs.GDT.Limit)
	fmt.Printf("  CS: Base=0x%x, Limit=0x%x, Selector=0x%x, L=%d\n",
		sregs.CS.Base, sregs.CS.Limit, sregs.CS.Selector, sregs.CS.L)

	// Set SREGS
	_, _, errno = ioctl(uintptr(vcpu.fd), KVM_SET_SREGS, uintptr(unsafe.Pointer(&sregs)))
	if errno != 0 {
		return fmt.Errorf("KVM_SET_SREGS failed: %v", errno)
	}

	// Setup REGS
	regs := KVMRegs{
		RIP:    KERNEL_LOAD_ADDR,
		RFLAGS: 0x2,
		RSP:    0x8000,
	}

	fmt.Printf("Setting general registers...\n")
	fmt.Printf("  RIP: 0x%x\n", regs.RIP)
	fmt.Printf("  RFLAGS: 0x%x\n", regs.RFLAGS)
	fmt.Printf("  RSP: 0x%x\n", regs.RSP)

	_, _, errno = ioctl(uintptr(vcpu.fd), KVM_SET_REGS, uintptr(unsafe.Pointer(&regs)))
	if errno != 0 {
		return fmt.Errorf("KVM_SET_REGS failed: %v", errno)
	}

	return nil
}

func uint64ToBytes(val uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(val)
	b[1] = byte(val >> 8)
	b[2] = byte(val >> 16)
	b[3] = byte(val >> 24)
	b[4] = byte(val >> 32)
	b[5] = byte(val >> 40)
	b[6] = byte(val >> 48)
	b[7] = byte(val >> 56)
	return b
}

func (vcpu *VCPU) Close() error {
	if vcpu.mmap != nil {
		if err := syscall.Munmap(vcpu.mmap); err != nil {
			return err
		}
	}
	if vcpu.fd != -1 {
		if err := syscall.Close(vcpu.fd); err != nil {
			return err
		}
	}
	return nil
}
