package vcpu

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	KVM_CREATE_VCPU        = 0xAE41
	KVM_GET_VCPU_MMAP_SIZE = 0xAE04
	KVM_RUN                = 0xAE80
	KVM_GET_REGS           = 0x8090
	KVM_SET_REGS           = 0x4090
)

// X86Regs represents the general purpose registers
type X86Regs struct {
	Rax    uint64
	Rbx    uint64
	Rcx    uint64
	Rdx    uint64
	Rsi    uint64
	Rdi    uint64
	Rsp    uint64
	Rbp    uint64
	R8     uint64
	R9     uint64
	R10    uint64
	R11    uint64
	R12    uint64
	R13    uint64
	R14    uint64
	R15    uint64
	Rip    uint64
	Rflags uint64
}

type VCPU struct {
	fd   int
	mmap []byte
	regs X86Regs
	vmfd int
	id   int
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

// SetRegisters sets the general purpose registers
func (vcpu *VCPU) SetRegisters(regs *X86Regs) error {
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(vcpu.fd),
		KVM_SET_REGS,
		uintptr(unsafe.Pointer(regs)),
	)
	if errno != 0 {
		return fmt.Errorf("failed to set registers: %v", errno)
	}
	return nil
}

// GetRegisters gets the current register values
func (vcpu *VCPU) GetRegisters() (*X86Regs, error) {
	regs := &X86Regs{}
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(vcpu.fd),
		KVM_GET_REGS,
		uintptr(unsafe.Pointer(regs)),
	)
	if errno != 0 {
		return nil, fmt.Errorf("failed to get registers: %v", errno)
	}
	return regs, nil
}
