package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ntdll               = syscall.NewLazyDLL("ntdll.dll")
	ntReadVirtualMemory = ntdll.NewProc("NtReadVirtualMemory")
)

func getModuleBaseAddress(pid int, moduleName string) (uintptr, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, uint32(pid))
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var me32 windows.ModuleEntry32
	me32.Size = uint32(unsafe.Sizeof(me32))

	if windows.Module32First(snapshot, &me32) != nil {
		return 0, fmt.Errorf("Module32First failed")
	}

	for {
		if strings.EqualFold(windows.UTF16ToString(me32.Module[:]), moduleName) {
			return uintptr(me32.ModBaseAddr), nil
		}
		if windows.Module32Next(snapshot, &me32) != nil {
			break
		}
	}

	return 0, fmt.Errorf("module not found")
}

func getProcessHandle(pid int) (windows.Handle, error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
}

func findProcessId(name string) (int, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}

	defer func() { _ = windows.CloseHandle(windows.Handle(snapshot)) }()

	for {
		var process windows.ProcessEntry32
		process.Size = uint32(unsafe.Sizeof(process))
		if windows.Process32Next(windows.Handle(snapshot), &process) != nil {
			break
		}
		if strings.EqualFold(windows.UTF16ToString(process.ExeFile[:]), name) {
			return int(process.ProcessID), nil
		}
	}
	return 0, fmt.Errorf("module not found")
}

func readMemoryNt(process windows.Handle, address uintptr, size int) ([]byte, error) {
	buffer := make([]byte, size)
	var bytesRead uintptr

	// Call NtReadVirtualMemory
	status, _, _ := ntReadVirtualMemory.Call(
		uintptr(process),
		address,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)),
	)
	if status != 0 {
		return nil, fmt.Errorf("NtReadVirtualMemory failed with status: 0x%x", status)
	}

	return buffer, nil
}

func readSafe(process windows.Handle, address uintptr, value interface{}) error {
	size := int(reflect.TypeOf(value).Elem().Size())
	buffer, err := readMemoryNt(process, address, size)
	if err != nil {
		return err
	}

	defer func() {
		for i := range buffer {
			buffer[i] = 0
		}
	}()

	switch v := value.(type) {
	case *int32:
		*v = int32(binary.LittleEndian.Uint32(buffer))
	case *uint32:
		*v = binary.LittleEndian.Uint32(buffer)
	case *float32:
		*v = math.Float32frombits(binary.LittleEndian.Uint32(buffer))
	case *int64:
		*v = int64(binary.LittleEndian.Uint64(buffer))
	case *uint64:
		*v = binary.LittleEndian.Uint64(buffer)
	case *float64:
		*v = math.Float64frombits(binary.LittleEndian.Uint64(buffer))
	case *uintptr:
		*v = uintptr(binary.LittleEndian.Uint64(buffer))
	case *string:
		*v = string(buffer)
	case *Vector3:
		v.X = math.Float32frombits(binary.LittleEndian.Uint32(buffer[0:4]))
		v.Y = math.Float32frombits(binary.LittleEndian.Uint32(buffer[4:8]))
		v.Z = math.Float32frombits(binary.LittleEndian.Uint32(buffer[8:12]))
	default:
		err = binary.Read(bytes.NewReader(buffer), binary.LittleEndian, value)
		if err != nil {
			return err
		}
	}
	return nil
}

func cleanHandle(handle windows.Handle) {
	_ = windows.CloseHandle(handle) // Ensure handle is closed
}
