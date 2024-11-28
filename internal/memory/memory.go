package memory

import (
	"fmt"
	"minivisor/internal/vcpu"
	"minivisor/internal/vmm"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	BOOT_PARAM_ADDR  = 0x10000
	CMDLINE_ADDR     = 0x20000
	KERNEL_LOAD_ADDR = 0x100000  // 1MB mark
	INITRD_LOAD_ADDR = 0x1000000 // 16MB mark

	CMDLINE = "console=ttyS0 earlyprintk=serial,ttyS0 debug nokaslr"
)

type VM struct {
	FD     int
	Memory *vmm.VMMemory
	Vcpu   *vcpu.VCPU
}

type BootParams struct {
	SetupSects    uint8
	RootFlags     uint16
	SysSize       uint32
	RamSize       uint32
	VideoPMode    uint16
	RootDev       uint16
	Signature     uint16 // Must be 0xAA55
	JumpInst      uint16
	Header        uint32 // Must be "HdrS" (0x53726448)
	Version       uint16
	TypeOfLoader  uint8
	LoadFlags     uint8
	SetupMoveSize uint16
	Code32Start   uint32
	RamdiskImage  uint32
	RamdiskSize   uint32
	CmdlinePtr    uint32
	HeapEndPtr    uint16
	ExtLoaderVer  uint8
	ExtLoaderType uint8
	CmdlineSize   uint32
}

func (vm *VM) Boot() error {
	// Initialize registers
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
	// Initialize memory if needed
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

	// Write command line
	cmdline := CMDLINE
	if err := vm.Memory.WritePhysical(CMDLINE_ADDR, []byte(cmdline+"\x00")); err != nil {
		return fmt.Errorf("failed to write command line: %v", err)
	}

	// Setup boot parameters
	bootParams := &BootParams{
		Signature:    0xAA55,
		Header:       0x53726448, // "HdrS"
		Version:      0x0202,     // Protocol version 2.02
		TypeOfLoader: 0xFF,       // Undefined bootloader
		LoadFlags:    0x01,       // LOADED_HIGH
		SetupSects:   0,          // Use default of 4
		RamdiskImage: INITRD_LOAD_ADDR,
		RamdiskSize:  uint32(len(initrd)),
		CmdlinePtr:   CMDLINE_ADDR,
		CmdlineSize:  uint32(len(cmdline) + 1),
		HeapEndPtr:   0xFE00, // Default heap end
		ExtLoaderVer: 0,      // No extended bootloader
	}

	fmt.Printf("Boot Parameters:\n")
	fmt.Printf("  Signature: 0x%x\n", bootParams.Signature)
	fmt.Printf("  Header: 0x%x\n", bootParams.Header)
	fmt.Printf("  Version: 0x%x\n", bootParams.Version)
	fmt.Printf("  RamdiskImage: 0x%x\n", bootParams.RamdiskImage)
	fmt.Printf("  RamdiskSize: %d\n", bootParams.RamdiskSize)
	fmt.Printf("  CmdlinePtr: 0x%x\n", bootParams.CmdlinePtr)
	fmt.Printf("  CmdlineSize: %d\n", bootParams.CmdlineSize)
	fmt.Printf("  Command line: %s\n", cmdline)

	// Write boot parameters
	bootParamsData := (*[unsafe.Sizeof(BootParams{})]byte)(unsafe.Pointer(bootParams))[:]
	if err := vm.Memory.WritePhysical(BOOT_PARAM_ADDR, bootParamsData); err != nil {
		return fmt.Errorf("failed to write boot parameters: %v", err)
	}

	// Load kernel at 1MB mark
	if err := vm.Memory.WritePhysical(KERNEL_LOAD_ADDR, kernel); err != nil {
		return fmt.Errorf("failed to load kernel: %v", err)
	}

	fmt.Printf("Kernel loaded at 0x%x, size: %d bytes\n", KERNEL_LOAD_ADDR, len(kernel))
	fmt.Printf("Initrd loaded at 0x%x, size: %d bytes\n", INITRD_LOAD_ADDR, len(initrd))

	// Load initrd
	if err := vm.Memory.WritePhysical(INITRD_LOAD_ADDR, initrd); err != nil {
		return fmt.Errorf("failed to load initrd: %v", err)
	}

	// Create VCPU if not exists
	if vm.Vcpu == nil {
		fmt.Printf("Creating new VCPU...\n")
		vcpu, err := vcpu.NewVCPU(vm.FD, 0)
		if err != nil {
			return fmt.Errorf("failed to create VCPU: %v", err)
		}
		vm.Vcpu = vcpu
		fmt.Printf("VCPU created successfully!\n")
	}

	return nil
}

func (vm *VM) SetupSerial() error {
	if vm.Memory == nil {
		return fmt.Errorf("VM memory not initialized")
	}
	return vm.Memory.SetupSerialPort()
}
