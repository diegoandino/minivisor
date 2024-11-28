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
)

type VM struct {
	FD     int
	Memory *vmm.VMMemory
	Vcpu   *vcpu.VCPU
}

type BootParams struct {
	SetupSects        uint8
	RootFlags         uint16
	SysSize           uint32
	RamSize           uint32
	VideoPMode        uint16
	RootDev           uint16
	Signature         uint16
	JumpInst          uint16
	Header            uint32
	Version           uint16
	RealModeSwitch    uint32
	StartSysSeg       uint16
	KernelVersion     uint16
	TypeOfLoader      uint8
	LoadFlags         uint8
	SetupMoveSize     uint16
	Code32Start       uint32
	RamdiskImage      uint32
	RamdiskSize       uint32
	BootSectKludge    uint32
	HeapEndPtr        uint16
	ExtLoaderVer      uint8
	ExtLoaderType     uint8
	CmdlinePtr        uint32
	InitrdAddrMax     uint32
	KernelAlignment   uint32
	RelocatableKernel uint8
	MinAlignment      uint8
	XLoadFlags        uint16
	CmdlineSize       uint32
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
	// Initialize memory management
	if vm.Memory == nil {
		memory, err := vmm.NewVMMemory(vm.FD)
		if err != nil {
			return fmt.Errorf("failed to initialize VM memory: %v", err)
		}
		vm.Memory = memory
	}

	// Setup main memory region
	if err := vm.Memory.SetupMemoryRegion(0, 0, vmm.MEM_SIZE); err != nil {
		return fmt.Errorf("failed to setup main memory region: %v", err)
	}

	// Set up kernel command line
	cmdline := "console=ttyS0 earlyprintk=serial nokaslr"
	if err := vm.Memory.WritePhysical(CMDLINE_ADDR, []byte(cmdline+"\x00")); err != nil {
		return fmt.Errorf("failed to write command line: %v", err)
	}

	// Setup boot parameters
	bootParams := &BootParams{
		Signature:    0xAA55,
		Header:       0x53726448, // "HdrS"
		LoadFlags:    0x01,       // LOADED_HIGH
		TypeOfLoader: 0xFF,
		RamdiskImage: INITRD_LOAD_ADDR,
		RamdiskSize:  uint32(len(initrd)),
		CmdlinePtr:   CMDLINE_ADDR,
		CmdlineSize:  uint32(len(cmdline) + 1),
	}

	// Write boot parameters
	bootParamsData := (*[0x1000]byte)(unsafe.Pointer(bootParams))[:unsafe.Sizeof(*bootParams)]
	if err := vm.Memory.WritePhysical(BOOT_PARAM_ADDR, bootParamsData); err != nil {
		return fmt.Errorf("failed to write boot parameters: %v", err)
	}

	// Load kernel
	if err := vm.Memory.WritePhysical(KERNEL_LOAD_ADDR, kernel); err != nil {
		return fmt.Errorf("failed to load kernel: %v", err)
	}

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
