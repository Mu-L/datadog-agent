// Code generated by "stringer -output kprobe_types_string_linux.go -type=CudaEventType -linecomment"; DO NOT EDIT.

package ebpf

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[CudaEventTypeKernelLaunch-0]
	_ = x[CudaEventTypeMemory-1]
	_ = x[CudaEventTypeSync-2]
	_ = x[CudaEventTypeSetDevice-3]
	_ = x[CudaEventTypeVisibleDevicesSet-4]
	_ = x[CudaEventTypeCount-5]
}

const _CudaEventType_name = "CudaEventTypeKernelLaunchCudaEventTypeMemoryCudaEventTypeSyncCudaEventTypeSetDeviceCudaEventTypeVisibleDevicesSetCudaEventTypeCount"

var _CudaEventType_index = [...]uint8{0, 25, 44, 61, 83, 113, 131}

func (i CudaEventType) String() string {
	if i >= CudaEventType(len(_CudaEventType_index)-1) {
		return "CudaEventType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _CudaEventType_name[_CudaEventType_index[i]:_CudaEventType_index[i+1]]
}
