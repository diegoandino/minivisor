package vmm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	KVM_SET_USER_MEMORY_REGION = 0x4020ae46
	PAGE_SIZE                  = 4096
	MEM_SIZE                   = 1024 * 1024 * 256 // 256MB of RAM for the VM
)

// KVMUserspaceMemoryRegion represents a memory region in the VM
type KVMUserspaceMemoryRegion struct {
	slot          uint32
	flags         uint32
	guestPhysAddr uint64
	memorySize    uint64
	userspaceAddr uint64
	_             [8]byte
}

type VMMemory struct {
	regions []KVMUserspaceMemoryRegion
	memory  []byte
	vmfd    int
}

func NewVMMemory(vmfd int) (*VMMemory, error) {
	// Allocate memory using mmap
	mem, err := unix.Mmap(-1, 0, MEM_SIZE,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_NORESERVE)
	if err != nil {
		return nil, fmt.Errorf("failed to mmap memory: %v", err)
	}

	return &VMMemory{
		regions: make([]KVMUserspaceMemoryRegion, 0),
		memory:  mem,
		vmfd:    vmfd,
	}, nil
}

func (vmm *VMMemory) Close() error {
	if vmm.memory != nil {
		if err := unix.Munmap(vmm.memory); err != nil {
			return fmt.Errorf("failed to unmap memory: %v", err)
		}
		vmm.memory = nil
	}
	return nil
}

func (vmm *VMMemory) SetupMemoryRegion(slot uint32, guestPhysAddr uint64, size uint64) error {
	if size == 0 {
		return fmt.Errorf("memory size cannot be 0")
	}

	region := KVMUserspaceMemoryRegion{
		slot:          slot,
		flags:         0,
		guestPhysAddr: guestPhysAddr,
		memorySize:    size,
		userspaceAddr: uint64(uintptr(unsafe.Pointer(&vmm.memory[0]))),
	}

	ptr := unsafe.Pointer(&region)

	// Set up the memory region in KVM
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(vmm.vmfd),
		uintptr(KVM_SET_USER_MEMORY_REGION),
		uintptr(ptr),
	)
	if errno != 0 {
		return fmt.Errorf("failed to set user memory region: %v", errno)
	}

	vmm.regions = append(vmm.regions, region)
	return nil
}

// Write data to guest physical memory
func (vmm *VMMemory) WritePhysical(physAddr uint64, data []byte) error {
	if physAddr+uint64(len(data)) > MEM_SIZE {
		return fmt.Errorf("write outside memory bounds")
	}
	copy(vmm.memory[physAddr:], data)
	return nil
}

// Read from guest physical memory
func (vmm *VMMemory) ReadPhysical(physAddr uint64, size uint64) ([]byte, error) {
	if physAddr+size > MEM_SIZE {
		return nil, fmt.Errorf("read outside memory bounds")
	}
	data := make([]byte, size)
	copy(data, vmm.memory[physAddr:physAddr+size])
	return data, nil
}
