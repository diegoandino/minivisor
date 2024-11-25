// main.go
package main

import (
	"fmt"
	"log"
	"minivisor/internal/memory"
	"os"

	"golang.org/x/sys/unix"
)

const (
	KVM_GET_API_VERSION    = 0xAE00
	KVM_CREATE_VM          = 0xAE01
	KVM_GET_VCPU_MMAP_SIZE = 0xAE04
)

type KVMSystem struct {
	fd int
}

// NewKVMSystem creates a new KVM system instance
func NewKVMSystem() (*KVMSystem, error) {
	fd, err := unix.Open("/dev/kvm", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/kvm: %v", err)
	}

	return &KVMSystem{fd: fd}, nil
}

// Close closes the KVM system
func (k *KVMSystem) Close() error {
	if k.fd != -1 {
		if err := unix.Close(k.fd); err != nil {
			return fmt.Errorf("failed to close KVM fd: %v", err)
		}
		k.fd = -1
	}
	return nil
}

// CheckAPI verifies KVM API version
func (k *KVMSystem) CheckAPI() (int, error) {
	version, err := unix.IoctlRetInt(k.fd, KVM_GET_API_VERSION)
	if err != nil {
		return 0, fmt.Errorf("failed to get KVM API version: %v", err)
	}
	if version != 12 {
		return version, fmt.Errorf("unexpected KVM API version: %d", version)
	}
	return version, nil
}

// CreateVM creates a new VM instance
func (k *KVMSystem) CreateVM() (int, error) {
	vmfd, err := unix.IoctlRetInt(k.fd, KVM_CREATE_VM)
	if err != nil {
		return -1, fmt.Errorf("failed to create VM: %v", err)
	}
	return vmfd, nil
}

// GetVCPUMMAPSize gets the required size of the vCPU memory mapping
func (k *KVMSystem) GetVCPUMMAPSize() (int, error) {
	size, err := unix.IoctlRetInt(k.fd, KVM_GET_VCPU_MMAP_SIZE)
	if err != nil {
		return 0, fmt.Errorf("failed to get vCPU mmap size: %v", err)
	}
	return size, nil
}

func main() {
	// Enable debug output
	fmt.Printf("Starting KVM initialization...\n")

	kvm, err := NewKVMSystem()
	if err != nil {
		log.Fatalf("Failed to create KVM: %v", err)
	}
	defer kvm.Close()
	fmt.Printf("KVM system created successfully\n")

	// Create VM
	vmfd, err := kvm.CreateVM()
	if err != nil {
		log.Fatalf("Failed to create VM: %v", err)
	}
	fmt.Printf("VM created successfully with fd: %d\n", vmfd)

	// Create VM instance
	vm := &memory.VM{FD: vmfd}
	defer vm.Close()

	// Read kernel and initrd files
	kernel, err := os.ReadFile("kernel/bzImage")
	if err != nil {
		log.Fatalf("Failed to read kernel: %v", err)
	}
	fmt.Printf("Kernel read successfully, size: %d bytes\n", len(kernel))

	initrd, err := os.ReadFile("kernel/initramfs.img")
	if err != nil {
		log.Fatalf("Failed to read initrd: %v", err)
	}
	fmt.Printf("Initrd read successfully, size: %d bytes\n", len(initrd))

	// Setup memory and load kernel
	fmt.Printf("Setting up kernel memory...\n")
	if err := vm.SetupKernelMemory(kernel, initrd); err != nil {
		log.Fatalf("Failed to setup kernel memory: %v", err)
	}
	fmt.Printf("Kernel memory setup completed successfully\n")
}
