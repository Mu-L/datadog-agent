// Code generated by "stringer -type=ProbeKind -linecomment -output probe_kind_string.go"; DO NOT EDIT.

package ir

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ProbeKindLog-1]
	_ = x[ProbeKindSpan-2]
	_ = x[ProbeKindMetric-3]
	_ = x[ProbeKindSnapshot-4]
}

const _ProbeKind_name = "ProbeKindLogProbeKindSpanProbeKindMetricProbeKindSnapshot"

var _ProbeKind_index = [...]uint8{0, 12, 25, 40, 57}

func (i ProbeKind) String() string {
	i -= 1
	if i >= ProbeKind(len(_ProbeKind_index)-1) {
		return "ProbeKind(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _ProbeKind_name[_ProbeKind_index[i]:_ProbeKind_index[i+1]]
}
