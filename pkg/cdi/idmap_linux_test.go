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
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// helperEnvVar triggers the helper mode of TestCanIDMapMountsInUserNamespace.
const helperEnvVar = "CDI_TEST_CAN_IDMAP_MOUNTS_HELPER"

// TestCanIDMapMountsInUserNamespace verifies that we don't consider idmapped
// mounts available in a process which runs in a user namespace other than the
// initial one. This is the environment rootless podman applies CDI edits in:
// the process is UID 0 and has CAP_SYS_ADMIN, but only within its own user
// namespace, so the kernel refuses to set up idmapped mounts for it.
func TestCanIDMapMountsInUserNamespace(t *testing.T) {
	if os.Getenv(helperEnvVar) == "1" {
		fmt.Printf("uid=%d canIDMapMounts=%v\n", os.Getuid(), canIDMapMounts())
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestCanIDMapMountsInUserNamespace")
	cmd.Env = append(os.Environ(), helperEnvVar+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("failed to run helper in a new user namespace (%v): %s", err, out)
	}

	require.Contains(t, string(out), "uid=0", "helper should be UID 0 in its user namespace")
	require.Contains(t, string(out), "canIDMapMounts=false",
		"idmapped mounts must not be considered available outside the initial user namespace")
}

// TestCanIDMapMountsAgreesWithProcfs cross-checks host detection against an
// independent implementation based on procfs text files.
func TestCanIDMapMountsAgreesWithProcfs(t *testing.T) {
	expected := inInitUserNamespaceByUIDMap(t) && hasCapSysAdminByStatus(t)
	require.Equal(t, expected, canIDMapMounts())
}

// inInitUserNamespaceByUIDMap reports whether /proc/self/uid_map contains the
// full identity mapping, which only the initial user namespace has in practice.
func inInitUserNamespaceByUIDMap(t *testing.T) bool {
	uidMap, err := os.ReadFile("/proc/self/uid_map")
	require.NoError(t, err)

	return strings.Join(strings.Fields(string(uidMap)), " ") == "0 0 4294967295"
}

// hasCapSysAdminByStatus reports whether the effective capability set in
// /proc/self/status contains CAP_SYS_ADMIN (bit 21).
func hasCapSysAdminByStatus(t *testing.T) bool {
	status, err := os.ReadFile("/proc/self/status")
	require.NoError(t, err)

	for _, line := range strings.Split(string(status), "\n") {
		caps, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		var effective uint64
		_, err := fmt.Sscanf(strings.TrimSpace(caps), "%x", &effective)
		require.NoError(t, err)

		return effective&(1<<21) != 0
	}

	t.Fatal("no CapEff line in /proc/self/status")
	return false
}
