package vcpu

import (
	"fmt"
	"syscall"
	"unsafe"
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

	// IO specific data
	IO struct {
		Direction  uint8 // 0 = in, 1 = out
		Size       uint8 // 1, 2 or 4
		Port       uint16
		Count      uint32
		DataOffset uint64
	}
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
)

type VCPU struct {
	fd   int
	mmap []byte
	vmfd int
	id   int
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

func (vcpu *VCPU) Run() error {
	run := (*KVMRun)(unsafe.Pointer(&vcpu.mmap[0]))

	fmt.Printf("Starting VCPU run loop\n")

	for {
		_, _, errno := ioctl(uintptr(vcpu.fd), KVM_RUN, 0)
		if errno != 0 {
			return fmt.Errorf("KVM_RUN failed: %v", errno)
		}

		switch run.ExitReason {
		case KVM_EXIT_IO:
			// Handle I/O (typically console output)
			if run.IO.Direction == 1 { // OUT
				switch run.IO.Port {
				case SERIAL_PORT_COM1:
					offset := run.IO.DataOffset
					size := uint64(run.IO.Size) * uint64(run.IO.Count)
					data := vcpu.mmap[offset : offset+size]
					fmt.Printf("%s", string(data))
				}
			}

		case KVM_EXIT_INTERNAL_ERROR:
			return fmt.Errorf("KVM internal error")

		case KVM_EXIT_SHUTDOWN:
			fmt.Printf("Guest shutdown requested\n")
			return nil

		case KVM_EXIT_HLT:
			fmt.Printf("CPU halted\n")
			return nil

		default:
			fmt.Printf("Unhandled exit reason: %d\n", run.ExitReason)
			return fmt.Errorf("unhandled exit reason: %d", run.ExitReason)
		}
	}
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

func (vcpu *VCPU) InitializeRegisters() error {
	// Get current SREGS
	sregs := KVMSRegs{}
	_, _, errno := ioctl(
		uintptr(vcpu.fd),
		trickGo(KVM_GET_SREGS),
		uintptr(unsafe.Pointer(&sregs)),
	)
	if errno != 0 {
		return fmt.Errorf("KVM_GET_SREGS failed: %v", errno)
	}

	// Simple setup like the example
	sregs.CS.Base = 0
	sregs.CS.Selector = 0

	// Set SREGS
	_, _, errno = ioctl(
		uintptr(vcpu.fd),
		KVM_SET_SREGS,
		uintptr(unsafe.Pointer(&sregs)),
	)
	if errno != 0 {
		return fmt.Errorf("KVM_SET_SREGS failed: %v", errno)
	}

	// Setup REGS
	regs := KVMRegs{
		RIP:    0x1000, // Entry point
		RAX:    2,
		RBX:    2,
		RFLAGS: 0x2,
	}

	_, _, errno = ioctl(
		uintptr(vcpu.fd),
		KVM_SET_REGS,
		uintptr(unsafe.Pointer(&regs)),
	)
	if errno != 0 {
		return fmt.Errorf("KVM_SET_REGS failed: %v", errno)
	}

	return nil
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
