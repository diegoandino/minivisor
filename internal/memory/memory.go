package memory

import (
	"fmt"
	"minivisor/internal/vcpu"
	"minivisor/internal/vmm"

	"golang.org/x/sys/unix"
)

const (
	KERNEL_LOAD_ADDR = 0x100000  // 1MB mark
	INITRD_LOAD_ADDR = 0x1000000 // 16MB mark
)

type VM struct {
	FD     int
	Memory *vmm.VMMemory
	Vcpu   *vcpu.VCPU
}

func (vm *VM) Boot() error {
	// Initialize registers
	/* if err := vm.Vcpu.TestRegisters(); err != nil {
		return fmt.Errorf("register test failed: %v", err)
	} */

	if err := vm.Vcpu.InitializeRegisters(); err != nil {
		return fmt.Errorf("failed to initialize registers: %v", err)
	}

	fmt.Printf("Starting VCPU execution...\n")
	return vm.Vcpu.Run()
}

func (vm *VM) Close() error {
	if vm.Vcpu != nil {
		if err := vm.Vcpu.Close(); err != nil {
			return fmt.Errorf("failed to close VCPU: %v", err)
		}
	}
	if vm.Memory != nil {
		if err := vm.Memory.Close(); err != nil {
			return fmt.Errorf("failed to close memory: %v", err)
		}
	}
	if vm.FD != -1 {
		if err := unix.Close(vm.FD); err != nil {
			return fmt.Errorf("failed to close VM fd: %v", err)
		}
		vm.FD = -1
	}
	return nil
}

func (vm *VM) SetupKernelMemory(kernel []byte, initrd []byte) error {
	// Ensure we have memory management initialized
	if vm.Memory == nil {
		memory, err := vmm.NewVMMemory(vm.FD)
		if err != nil {
			return fmt.Errorf("failed to initialize VM memory: %v", err)
		}
		vm.Memory = memory
	}

	// Setup the main memory region
	if err := vm.Memory.SetupMemoryRegion(0, 0, vmm.MEM_SIZE); err != nil {
		return fmt.Errorf("failed to setup main memory region: %v", err)
	}

	// Load kernel at 1MB mark
	if err := vm.Memory.WritePhysical(KERNEL_LOAD_ADDR, kernel); err != nil {
		return fmt.Errorf("failed to load kernel: %v", err)
	}

	// Load initrd if provided
	if initrd != nil {
		if err := vm.Memory.WritePhysical(INITRD_LOAD_ADDR, initrd); err != nil {
			return fmt.Errorf("failed to load initrd: %v", err)
		}
	}

	// Setup initial VCPU state for kernel boot
	if vm.Vcpu == nil {
		fmt.Printf("Creating new VCPU...\n")
		vcpu, err := vcpu.NewVCPU(vm.FD, 0)
		if err != nil {
			return fmt.Errorf("failed to create VCPU: %v", err)
		}
		vm.Vcpu = vcpu
		fmt.Printf("VCPU created successfully!\n")
	}

	/* // Set initial registers for kernel boot
	regs := &vcpu.X86Regs{
		Rip:    KERNEL_LOAD_ADDR,
		Rflags: 0x2,    // Enable interrupts
		Rsp:    0x8000, // Initial stack pointer
	}

	if err := vm.Vcpu.SetRegisters(regs); err != nil {
		return fmt.Errorf("failed to set initial registers: %v", err)
	} */

	return nil
}
