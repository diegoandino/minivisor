package vcpu

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// IOCTL constants
	typeshift = 8
	nrshift   = 0
	sizeshift = 16
	dirshift  = 30

	// Direction bits
	none      = 0
	write     = 1
	read      = 2
	readwrite = 3

	// Masks
	nrmask   = 0xFF
	sizemask = 0x3FFF
	dirmask  = 0x3
)

const (
	// Control register flags
	CR0_PE = 1 << 0
	CR0_MP = 1 << 1
	CR0_ET = 1 << 4
	CR0_NE = 1 << 5
	CR0_WP = 1 << 16
	CR0_AM = 1 << 18
	CR0_PG = 1 << 31

	CR4_PAE = 1 << 5

	EFER_LME = 1 << 8
	EFER_LMA = 1 << 10

	// Memory layout
	PAGE_SIZE       = 0x1000 // 4KB
	PAGE_TABLE_BASE = 0x1000 // Start at 4KB boundary
	PDPT_BASE       = PAGE_TABLE_BASE + 0x1000
	PD_BASE         = PDPT_BASE + 0x1000
)

const (
	_IOC_NONE  = 0
	_IOC_WRITE = 1
	_IOC_READ  = 2

	_IOC_NRBITS   = 8
	_IOC_TYPEBITS = 8
	_IOC_SIZEBITS = 14
	_IOC_DIRBITS  = 2

	_IOC_NRSHIFT   = 0
	_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
	_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
	_IOC_DIRSHIFT  = _IOC_SIZESHIFT + _IOC_SIZEBITS

	KVMIO = 0xAE

	// VCPU Related IOCTLS
	KVM_CREATE_VCPU        = 0xAE41
	KVM_GET_VCPU_MMAP_SIZE = 0xAE04

	KVM_GET_SREGS = 0x8138 // _IOR(KVMIO, 0x83, struct kvm_sregs)
	KVM_SET_SREGS = 0x4138 // _IOW(KVMIO, 0x84, struct kvm_sregs)

	KVM_GET_REGS = 0x8090 // _IOR(KVMIO, 0x81, struct kvm_regs)
	KVM_SET_REGS = 0x4090 // _IOW(KVMIO, 0x82, struct kvm_regs)

	KVM_RUN = 0xAE80 // _IO(KVMIO, 0x80)

	// Exit Calls
	KVM_EXIT_IO               = 2
	KVM_EXIT_HLT              = 5
	KVM_EXIT_MMIO             = 6
	KVM_EXIT_INTERNAL_ERROR   = 17
	KVM_NR_INTERRUPTS         = 256
	KVM_EXIT_SHUTDOWN         = 8
	KVM_INTERRUPT_BITMAP_SIZE = (KVM_NR_INTERRUPTS + 63) / 64 // Size in uint64s

	KVM_SEGMENT_FLAGS_UNUSABLE = 1 << 0
	KVM_SEGMENT_FLAGS_PRESENT  = 1 << 7

	numInterrupts = 0x100
)

// Registers structure must match kernel's kvm_regs
type Registers struct {
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

// Segment represents a segment register
type Segment struct {
	Base     uint64 `align:"8"`
	Limit    uint32 `align:"4"`
	Selector uint16 `align:"2"`
	Type     uint8
	Present  uint8
	DPL      uint8
	DB       uint8
	S        uint8
	L        uint8
	G        uint8
	AVL      uint8
	Unusable uint8
	_        uint8 // padding
}

// SpecialRegisters structure must match kernel's kvm_sregs
type DTReg struct {
	Base    uint64 `align:"8"`
	Limit   uint16 `align:"2"`
	Padding [6]uint8
}

// Total: 304 bytes
type SpecialRegisters struct {
	CS               Segment   `align:"8"`
	DS               Segment   `align:"8"`
	ES               Segment   `align:"8"`
	FS               Segment   `align:"8"`
	GS               Segment   `align:"8"`
	SS               Segment   `align:"8"`
	TR               Segment   `align:"8"`
	LDT              Segment   `align:"8"`
	GDT              DTReg     `align:"8"`
	IDT              DTReg     `align:"8"`
	CR0              uint64    `align:"8"`
	CR2              uint64    `align:"8"`
	CR3              uint64    `align:"8"`
	CR4              uint64    `align:"8"`
	CR8              uint64    `align:"8"`
	EFER             uint64    `align:"8"`
	APIC_BASE        uint64    `align:"8"`
	INTERRUPT_BITMAP [3]uint64 `align:"8"`
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
	// Union of exit reasons follows
	IO struct {
		Direction  uint8 // 0 = in, 1 = out
		Size       uint8 // 1, 2 or 4
		Port       uint16
		Count      uint32
		DataOffset uint64 // relative to kvm_run start
	}
}

type VCPU struct {
	fd   int
	mmap []byte
	regs Registers
	vmfd int
	id   int
}

func init() {
	verifyStructureSizes()
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

func init() {
	// Print IOCTL numbers for verification
	fmt.Printf("IOCTL numbers:\n")
	fmt.Printf("  KVM_GET_SREGS: 0x%x\n", KVM_GET_SREGS)
	fmt.Printf("  KVM_SET_SREGS: 0x%x\n", KVM_SET_SREGS)
	fmt.Printf("  Size of SpecialRegisters: %d bytes\n", unsafe.Sizeof(SpecialRegisters{}))
}

func NewVCPU(vmfd int, id int) (*VCPU, error) {
	// Debug output
	fmt.Printf("Creating VCPU with vmfd: %d, id: %d\n", vmfd, id)

	// Create VCPU using ioctl
	vcpufd, err := unix.IoctlRetInt(vmfd, KVM_CREATE_VCPU)
	if err != nil {
		return nil, fmt.Errorf("failed to create VCPU %v", err)
	}
	fmt.Printf("VCPU fd created: %d\n", vcpufd)

	// Get the required mmap size
	vfd, err := unix.Open("/dev/kvm", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/kvm\n")
	}

	mmapSize, err := unix.IoctlRetInt(vfd, KVM_GET_VCPU_MMAP_SIZE)
	if err != nil {
		unix.Close(vcpufd)
		return nil, fmt.Errorf("failed to get VCPU mmap size: %v", mmapSize)
	}
	fmt.Printf("VCPU mmap size: %d bytes\n", mmapSize)

	// Mmap the VCPU region
	mem, err := unix.Mmap(
		vcpufd,
		0,
		mmapSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
	)
	if err != nil {
		unix.Close(vcpufd)
		return nil, fmt.Errorf("failed to mmap VCPU: %v", err)
	}

	return &VCPU{
		fd:   vcpufd,
		mmap: mem,
		vmfd: vmfd,
		id:   id,
	}, nil
}

func (vcpu *VCPU) Close() error {
	if vcpu.mmap != nil {
		if err := unix.Munmap(vcpu.mmap); err != nil {
			return fmt.Errorf("failed to unmap VCPU memory: %v", err)
		}
		vcpu.mmap = nil
	}
	if vcpu.fd != -1 {
		if err := unix.Close(vcpu.fd); err != nil {
			return fmt.Errorf("failed to close VCPU fd: %v", err)
		}
		vcpu.fd = -1
	}
	return nil
}

func (vcpu *VCPU) GetRegisters() (*Registers, error) {
	regs := &Registers{}
	if err := unix.IoctlSetInt(vcpu.fd, KVM_GET_REGS, int(uintptr(unsafe.Pointer(regs)))); err != nil {
		return nil, fmt.Errorf("failed to get registers: %v", err)
	}
	return regs, nil
}

func (vcpu *VCPU) SetRegisters(regs *Registers) error {
	if err := unix.IoctlSetInt(vcpu.fd, KVM_SET_REGS, int(uintptr(unsafe.Pointer(regs)))); err != nil {
		return fmt.Errorf("failed to set registers: %v", err)
	}
	return nil
}

func verifyStructureSizes() {
	fmt.Printf("Structure layout verification:\n")

	segmentSize := unsafe.Sizeof(Segment{})
	segmentAlign := unsafe.Alignof(Segment{})
	fmt.Printf("Segment: size=%d bytes, alignment=%d\n", segmentSize, segmentAlign)

	dtRegSize := unsafe.Sizeof(DTReg{})
	dtRegAlign := unsafe.Alignof(DTReg{})
	fmt.Printf("DTReg: size=%d bytes, alignment=%d\n", dtRegSize, dtRegAlign)

	sregsSize := unsafe.Sizeof(SpecialRegisters{})
	sregsAlign := unsafe.Alignof(SpecialRegisters{})
	fmt.Printf("SpecialRegisters: size=%d bytes, alignment=%d\n", sregsSize, sregsAlign)

	// Print offsets of key fields
	sregsType := reflect.TypeOf(SpecialRegisters{})
	for i := 0; i < sregsType.NumField(); i++ {
		field := sregsType.Field(i)
		offset := field.Offset
		fmt.Printf("Field %s offset: %d\n", field.Name, offset)
	}
}

func dumpSegment(name string, seg *Segment) {
	fmt.Printf("%s: Base=0x%x, Limit=0x%x, Selector=0x%x, Type=0x%x, P=%d, DPL=%d, DB=%d, S=%d, L=%d, G=%d\n",
		name, seg.Base, seg.Limit, seg.Selector, seg.Type, seg.Present, seg.DPL, seg.DB, seg.S, seg.L, seg.G)
}

func Ioctl(fd, op, arg uintptr) (uintptr, error) {
	res, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, op, arg)
	if errno != 0 {
		return res, errno
	}

	return res, nil
}

func memoryBarrier() {
	var a uint64
	atomic.LoadUint64(&a)
}

func calculateIOC(dir uint32, typ uint32, nr uint32, size uint32) uint32 {
	return (dir << _IOC_DIRSHIFT) |
		(typ << _IOC_TYPESHIFT) |
		(nr << _IOC_NRSHIFT) |
		(size << _IOC_SIZESHIFT)
}

func (vcpu *VCPU) GetSpecialRegisters() (*SpecialRegisters, error) {
	sregs := &SpecialRegisters{}
	size := uint32(unsafe.Sizeof(*sregs))

	// Calculate the IOCTL number
	ioctlNum := calculateIOC(_IOC_READ, KVMIO, 0x83, size)

	fmt.Printf("Debug: GetSpecialRegisters IOCTL=0x%x size=%d\n", ioctlNum, size)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(vcpu.fd),
		uintptr(ioctlNum),
		uintptr(unsafe.Pointer(sregs)),
	)

	if errno != 0 {
		return nil, fmt.Errorf("failed to get special registers: %v", errno)
	}

	return sregs, nil
}

func (vcpu *VCPU) SetSpecialRegisters(sregs *SpecialRegisters) error {
	size := uint32(unsafe.Sizeof(*sregs))

	// Calculate the IOCTL number
	ioctlNum := calculateIOC(_IOC_WRITE, KVMIO, 0x84, size)

	fmt.Printf("Debug: SetSpecialRegisters IOCTL=0x%x size=%d\n", ioctlNum, size)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(vcpu.fd),
		uintptr(ioctlNum),
		uintptr(unsafe.Pointer(sregs)),
	)

	if errno != 0 {
		return fmt.Errorf("failed to set special registers: %v", errno)
	}

	return nil
}

func (vcpu *VCPU) TestRegisters() error {
	fmt.Printf("Testing register operations...\n")

	sregs, err := vcpu.GetSpecialRegisters()
	if err != nil {
		fmt.Printf("Failed to get registers: %v\n", err)
		return err
	}

	fmt.Printf("Successfully got registers\n")
	fmt.Printf("CR0: 0x%x\n", sregs.CR0)
	fmt.Printf("CR4: 0x%x\n", sregs.CR4)
	fmt.Printf("EFER: 0x%x\n", sregs.EFER)

	return nil
}

// InitializeRegisters sets up the initial register state for kernel boot
func (vcpu *VCPU) InitializeRegisters() error {
	fmt.Printf("Initializing registers for long mode...\n")

	// Verify VCPU fd is valid
	if vcpu.fd <= 0 {
		return fmt.Errorf("invalid VCPU file descriptor: %d", vcpu.fd)
	}

	// First, set up page tables
	if err := vcpu.setupPageTables(); err != nil {
		return fmt.Errorf("failed to setup page tables: %v", err)
	}

	fmt.Printf("Attempting to get current special registers...\n")
	sregs, err := vcpu.GetSpecialRegisters()
	if err != nil {
		// Print more debug information
		fmt.Printf("VCPU fd: %d\n", vcpu.fd)
		fmt.Printf("Error getting special registers: %v\n", err)
		return fmt.Errorf("failed to get special registers: %v", err)
	}

	// Set up control registers for long mode
	sregs.CR3 = 0       // PML4 is at start of mmap
	sregs.CR4 = CR4_PAE // Enable PAE
	sregs.CR0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
	sregs.EFER = EFER_LME | EFER_LMA

	// Set up code segment
	sregs.CS = Segment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 0x10,
		Type:     11, // Code: execute/read, accessed
		Present:  1,
		DPL:      0,
		DB:       0,
		S:        1, // Code/data segment
		L:        1, // 64-bit mode
		G:        1, // 4KB granularity
	}

	// Set up data segments
	dataSeg := Segment{
		Base:     0,
		Limit:    0xffffffff,
		Selector: 0x18,
		Type:     3, // Data: read/write, accessed
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

	fmt.Printf("Setting special registers...\n")
	if err := vcpu.SetSpecialRegisters(sregs); err != nil {
		return fmt.Errorf("failed to set special registers: %v", err)
	}

	// Set up general purpose registers
	regs := &Registers{
		RIP:    0x100000, // Kernel entry point
		RFLAGS: 2,        // Only bit 1 set as required
		RSP:    0x8000,   // Initial stack pointer
	}

	fmt.Printf("Setting general registers...\n")
	if err := vcpu.SetRegisters(regs); err != nil {
		return fmt.Errorf("failed to set general registers: %v", err)
	}

	fmt.Printf("Register initialization completed\n")
	return nil
}

// Run starts executing the VCPU
func (vcpu *VCPU) Run() error {
	run := (*KVMRun)(unsafe.Pointer(&vcpu.mmap[0]))

	for {
		if err := unix.IoctlSetInt(vcpu.fd, KVM_RUN, 0); err != nil {
			return fmt.Errorf("KVM_RUN failed: %v", err)
		}

		switch run.ExitReason {
		case KVM_EXIT_HLT:
			fmt.Printf("CPU halted\n")
			return nil

		case KVM_EXIT_IO:
			// Handle I/O (typically console output)
			if run.IO.Direction == 1 { // OUT
				offset := run.IO.DataOffset
				//size := run.IO.Size * run.IO.Count
				size := run.IO.Size * uint8(run.IO.Count)
				data := vcpu.mmap[offset : offset+uint64(size)]
				fmt.Printf("%s", string(data))
			}

		case KVM_EXIT_INTERNAL_ERROR:
			return fmt.Errorf("KVM internal error")

		case KVM_EXIT_SHUTDOWN:
			fmt.Printf("Guest shutdown requested\n")
			return nil

		default:
			fmt.Printf("Unhandled exit reason: %d\n", run.ExitReason)
			return fmt.Errorf("unhandled exit reason: %d", run.ExitReason)
		}
	}
}

// Helper function to write to guest physical memory through MMIO
func (vcpu *VCPU) writePhysicalMemory(addr uint64, data []byte) error {
	if addr >= uint64(len(vcpu.mmap)) || int(addr)+len(data) > len(vcpu.mmap) {
		return fmt.Errorf("memory write out of bounds: addr=0x%x size=%d mmap_size=%d",
			addr, len(data), len(vcpu.mmap))
	}
	copy(vcpu.mmap[addr:], data)
	return nil
}

// Helper function to convert uint64 to byte slice
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
