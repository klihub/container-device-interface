package specs

import "os"

// Spec is the base configuration for CDI
type Spec struct {
	Version string `json:"cdiVersion" yaml:"cdiVersion"`
	Kind    string `json:"kind"       yaml:"kind"`
	// Annotations add meta information per CDI spec. Note these are CDI-specific and do not affect container metadata.
	// Added in v0.6.0.
	Annotations    map[string]string `json:"annotations,omitempty"    yaml:"annotations,omitempty"`
	Devices        []Device          `json:"devices"                  yaml:"devices"`
	ContainerEdits ContainerEdits    `json:"containerEdits,omitempty" yaml:"containerEdits,omitempty"`
}

// Device is a "Device" a container runtime can add to a container
type Device struct {
	Name string `json:"name" yaml:"name"`
	// Annotations add meta information per device. Note these are CDI-specific and do not affect container metadata.
	// Added in v0.6.0.
	Annotations    map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	ContainerEdits ContainerEdits    `json:"containerEdits"        yaml:"containerEdits"`
}

// ContainerEdits are edits a container runtime must make to the OCI spec to expose the device.
type ContainerEdits struct {
	Env            []string             `json:"env,omitempty"            yaml:"env,omitempty"`
	DeviceNodes    []*DeviceNode        `json:"deviceNodes,omitempty"    yaml:"deviceNodes,omitempty"`
	NetDevices     []*LinuxNetDevice    `json:"netDevices,omitempty"     yaml:"netDevices,omitempty"` // Added in v1.1.0
	Hooks          []*Hook              `json:"hooks,omitempty"          yaml:"hooks,omitempty"`
	Mounts         []*Mount             `json:"mounts,omitempty"         yaml:"mounts,omitempty"`
	IntelRdt       *IntelRdt            `json:"intelRdt,omitempty"       yaml:"intelRdt,omitempty"`       // Added in v0.7.0
	AdditionalGIDs []uint32             `json:"additionalGids,omitempty" yaml:"additionalGids,omitempty"` // Added in v0.7.0
	Annotations    ContainerAnnotations `json:"annotations,omitempty"     yaml:"annotations,omitempty"`   // Added in v1.2.0
}

// DeviceNode represents a device node that needs to be added to the OCI spec.
type DeviceNode struct {
	Path        string       `json:"path"                  yaml:"path"`
	HostPath    string       `json:"hostPath,omitempty"    yaml:"hostPath,omitempty"` // Added in v0.5.0
	Type        string       `json:"type,omitempty"        yaml:"type,omitempty"`
	Major       int64        `json:"major,omitempty"       yaml:"major,omitempty"`
	Minor       int64        `json:"minor,omitempty"       yaml:"minor,omitempty"`
	FileMode    *os.FileMode `json:"fileMode,omitempty"    yaml:"fileMode,omitempty"`
	Permissions string       `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	UID         *uint32      `json:"uid,omitempty"         yaml:"uid,omitempty"`
	GID         *uint32      `json:"gid,omitempty"         yaml:"gid,omitempty"`
}

// Mount represents a mount that needs to be added to the OCI spec.
type Mount struct {
	HostPath      string   `json:"hostPath"          yaml:"hostPath"`
	ContainerPath string   `json:"containerPath"     yaml:"containerPath"`
	Options       []string `json:"options,omitempty" yaml:"options,omitempty"`
	Type          string   `json:"type,omitempty"    yaml:"type,omitempty"` // Added in v0.4.0
}

// Hook represents a hook that needs to be added to the OCI spec.
type Hook struct {
	HookName string   `json:"hookName"          yaml:"hookName"`
	Path     string   `json:"path"              yaml:"path"`
	Args     []string `json:"args,omitempty"    yaml:"args,omitempty"`
	Env      []string `json:"env,omitempty"     yaml:"env,omitempty"`
	Timeout  *int     `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// IntelRdt describes the Linux IntelRdt parameters to set in the OCI spec.
type IntelRdt struct {
	ClosID           string   `json:"closID,omitempty"           yaml:"closID,omitempty"`
	L3CacheSchema    string   `json:"l3CacheSchema,omitempty"    yaml:"l3CacheSchema,omitempty"`
	MemBwSchema      string   `json:"memBwSchema,omitempty"      yaml:"memBwSchema,omitempty"`
	Schemata         []string `json:"schemata,omitempty"         yaml:"schemata,omitempty"`         // Added in v1.1.0.
	EnableMonitoring bool     `json:"enableMonitoring,omitempty" yaml:"enableMonitoring,omitempty"` // Added in v1.1.0.
}

// LinuxNetDevice represents an OCI LinuxNetDevice to be added to the OCI Spec.
type LinuxNetDevice struct {
	HostInterfaceName string `json:"hostInterfaceName" yaml:"hostInterfaceName"`
	Name              string `json:"name"   yaml:"name"`
}

// AnnotationPrefix is the prefix for CDI container annotation keys.
const AnnotationPrefix = "cdi.k8s.io/"

// ContainerAnnotations represents one or more annotations to be injected into the OCI Spec of
// a container. Evenry injected annotation key will be prefixed with "cdi.k8s.io/".
type ContainerAnnotations map[string]*ContainerAnnotationValue

// ContainerAnnotationValue represents an annotation value.
type ContainerAnnotationValue struct {
	Value      string             `json:"value" yaml:"value"`
	Format     ValueFormat        `json:"format,omitempty" yaml:"format,omitempty"`
	OnConflict ConflictResolution `json:"onConflict,omitempty" yaml:"onConflict,omitempty"`
}

// ValueFormat describes how annotation values should be interpreted for conflict resolution.
// If CDI device injection should inject a container annotation and the annotation key already
// has a value, Format/ValueFormat and OnConflict/ConflictResolution collectively describe how
// to resolve the conflict. ConflictError, ConflictOverwrite and ConflictKeepOld fail device
// injection, overwrite the old value, or keep the old value respectively. ConflictAppend for
// stringSlice Format appends the new value to the old value by demarshalling, appending and
// marshalling the new value again.
type ValueFormat string

const (
	// FormatImpliedString is the default/implied string annotation value format.
	FormatImpliedString ValueFormat = ""
	// FormatString is indicates a string annotation value format.
	FormatString ValueFormat = "string"
	// FormatStringSlice indicates a string slice annotation value format
	FormatStringSlice ValueFormat = "stringSlice"
)

// ConflictResolution describes how container annotation conflicts should be resolved.
type ConflictResolution string

const (
	// ConflictImpliedError is the default/implied 'error on conflict' resolution strategy.
	ConflictImpliedError ConflictResolution = ""
	// ConflictError indicates an 'error on conflict' resolution strategy.
	ConflictError ConflictResolution = "error"
	// ConflictPickNew indicates a 'pick new value' resolution strategy.
	ConflictPickNew ConflictResolution = "pickNew"
	// ConflictPickOld indicates a 'pick old value' resolution strategy.
	ConflictPickOld ConflictResolution = "pickOld"
	// ConflictAppend indicates a 'append new value to old value' resolution strategy.
	// This is only valid for values of stringSlice format.
	ConflictAppend ConflictResolution = "append" // (string slice) value is appended
)
