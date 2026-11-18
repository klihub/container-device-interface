/*
Copyright © 2026 The CDI Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cdi

import (
	"golang.org/x/sys/unix"
)

const (
	// userNsInitIno is the fixed inode number the kernel assigns to the
	// initial user namespace (PROC_USER_INIT_INO in include/linux/proc_ns.h).
	userNsInitIno = 0xEFFFFFFD

	// capUserHeaderVersion3 is _LINUX_CAPABILITY_VERSION_3, the 64-bit
	// capability ABI available since Linux 2.6.26.
	capUserHeaderVersion3 = 0x20080522
)

// canIDMapMounts reports whether idmapped mounts can be set up in this
// environment. Setting one up requires CAP_SYS_ADMIN in the initial user
// namespace, so being UID 0 is not enough: a process in any other user
// namespace get EPERM. For instance rootless podman as UID 0 within its
// own user namespace.
//
// Note that this says nothing about whether the filesystem backing any
// particular mount source supports idmapping; that can only be found out
// by trying.
func canIDMapMounts() bool {
	return inInitUserNamespace() && hasCapSysAdmin()
}

// inInitUserNamespace reports whether this process runs in the initial user
// namespace, by comparing the inode of /proc/self/ns/user against the one
// the kernel reserves for that namespace.
func inInitUserNamespace() bool {
	var st unix.Stat_t

	if err := unix.Stat("/proc/self/ns/user", &st); err != nil {
		return false
	}

	return st.Ino == userNsInitIno
}

// hasCapSysAdmin reports whether CAP_SYS_ADMIN is in the effective
// capability set of this process.
func hasCapSysAdmin() bool {
	var (
		hdr  = unix.CapUserHeader{Version: capUserHeaderVersion3}
		data [2]unix.CapUserData
	)

	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}

	// CAP_SYS_ADMIN (21) is in the first 32-bit capability block.
	return data[0].Effective&(1<<unix.CAP_SYS_ADMIN) != 0
}
