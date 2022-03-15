/*
   Copyright © 2021 The CDI Authors

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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/go-multierror"
	oci "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

// Option is an option to change some aspect of default CDI behavior.
type Option func(*Cache) error

// Cache stores CDI Specs loaded from Spec directories.
type Cache struct {
	sync.RWMutex
	specDirs  []string
	specs     map[string][]*Spec
	devices   map[string]*Device
	errors    map[string][]error
	dirErrors map[string]error

	selfRefresh bool
	createDirs  bool
	watch       *watch
}

// WithSelfRefresh returns an option to control automatic Cache refresh.
// Normally, when self-refresh is enabled the list of Spec directories are
// monitored and the Cache is automatically refreshed whenever a change is
// detected. This option can disable this behavior, requiring the cache to
// be manually refreshed.
func WithSelfRefresh(selfRefresh bool) Option {
	return func(c *Cache) error {
		c.selfRefresh = selfRefresh
		return nil
	}
}

// NewCache creates a new CDI Cache. The cache is populated from a set
// of CDI Spec directories. These can be specified using a WithSpecDirs
// option. The default set of directories is exposed in DefaultSpecDirs.
func NewCache(options ...Option) (*Cache, error) {
	c := &Cache{
		selfRefresh: true,
		watch:       &watch{},
	}

	WithSpecDirs(DefaultSpecDirs...)(c)

	c.Lock()
	defer c.Unlock()

	return c, c.configure(options...)
}

// Configure applies options to the Cache. Updates and refreshes the
// Cache if options have changed.
func (c *Cache) Configure(options ...Option) error {
	if len(options) == 0 {
		return nil
	}

	c.Lock()
	defer c.Unlock()

	return c.configure(options...)
}

// Configure the Cache. Start/stop CDI Spec directory watch, refresh
// the Cache if necessary.
func (c *Cache) configure(options ...Option) error {
	var (
		dirs []string
		err  error
	)

	for _, o := range options {
		if err = o(c); err != nil {
			return errors.Wrapf(err, "failed to apply cache options")
		}
	}

	c.dirErrors = make(map[string]error)
	if c.createDirs {
		c.createMissingDirs()
	}

	c.watch.stop()
	if c.selfRefresh {
		dirs, err = c.watch.setup(c.specDirs, c.dirErrors)
		if err != nil {
			return err
		}
		c.watch.start(&c.RWMutex, c.refresh)
		c.specDirs = dirs
	}
	c.refresh()

	return nil
}

// Refresh rescans the CDI Spec directories and refreshes the Cache.
// In manual refresh mode the cache is always refreshed. In self-
// refresh mode the cache is only refreshed if it is out of date.
func (c *Cache) Refresh() error {
	c.Lock()
	defer c.Unlock()

	// collect cached errors globally as a single multierror
	cachedErrors := func() error {
		var result error
		for _, err := range c.errors {
			result = multierror.Append(result, err...)
		}
		return result
	}

	// We need to refresh if
	// - we're in manual refresh mode, or
	// - in self-refresh mode a missing Spec dir appears (added to watch)
	if !c.selfRefresh {
		return c.refresh()
	}

	return cachedErrors()
}

// Rescan CDI Spec directories and refresh the Cache.
func (c *Cache) refresh() error {
	var (
		specs      = map[string][]*Spec{}
		devices    = map[string]*Device{}
		conflicts  = map[string]struct{}{}
		specErrors = map[string][]error{}
		result     []error
	)

	// collect errors per spec file path and once globally
	collectError := func(err error, paths ...string) {
		result = append(result, err)
		for _, path := range paths {
			specErrors[path] = append(specErrors[path], err)
		}
	}
	// resolve conflicts based on device Spec priority (order of precedence)
	resolveConflict := func(name string, dev *Device, old *Device) bool {
		devSpec, oldSpec := dev.GetSpec(), old.GetSpec()
		devPrio, oldPrio := devSpec.GetPriority(), oldSpec.GetPriority()
		switch {
		case devPrio > oldPrio:
			return false
		case devPrio == oldPrio:
			devPath, oldPath := devSpec.GetPath(), oldSpec.GetPath()
			collectError(errors.Errorf("conflicting device %q (specs %q, %q)",
				name, devPath, oldPath), devPath, oldPath)
			conflicts[name] = struct{}{}
		}
		return true
	}

	_ = scanSpecDirs(c.specDirs, func(path string, priority int, spec *Spec, err error) error {
		path = filepath.Clean(path)
		if err != nil {
			collectError(errors.Wrapf(err, "failed to load CDI Spec"), path)
			return nil
		}

		vendor := spec.GetVendor()
		specs[vendor] = append(specs[vendor], spec)

		for _, dev := range spec.devices {
			qualified := dev.GetQualifiedName()
			other, ok := devices[qualified]
			if ok {
				if resolveConflict(qualified, dev, other) {
					continue
				}
			}
			devices[qualified] = dev
		}

		return nil
	})

	for conflict := range conflicts {
		delete(devices, conflict)
	}

	c.specs = specs
	c.devices = devices
	c.errors = specErrors

	if len(result) > 0 {
		return multierror.Append(nil, result...)
	}

	return nil
}

// InjectDevices injects the given qualified devices to an OCI Spec. It
// returns any unresolvable devices and an error if injection fails for
// any of the devices.
func (c *Cache) InjectDevices(ociSpec *oci.Spec, devices ...string) ([]string, error) {
	var unresolved []string

	if ociSpec == nil {
		return devices, errors.Errorf("can't inject devices, nil OCI Spec")
	}

	c.RLock()
	defer c.RUnlock()

	edits := &ContainerEdits{}
	specs := map[*Spec]struct{}{}

	for _, device := range devices {
		d := c.devices[device]
		if d == nil {
			unresolved = append(unresolved, device)
			continue
		}
		if _, ok := specs[d.GetSpec()]; !ok {
			specs[d.GetSpec()] = struct{}{}
			edits.Append(d.GetSpec().edits())
		}
		edits.Append(d.edits())
	}

	if unresolved != nil {
		return unresolved, errors.Errorf("unresolvable CDI devices %s",
			strings.Join(devices, ", "))
	}

	if err := edits.Apply(ociSpec); err != nil {
		return nil, errors.Wrap(err, "failed to inject devices")
	}

	return nil, nil
}

// GetDevice returns the cached device for the given qualified name.
func (c *Cache) GetDevice(device string) *Device {
	c.RLock()
	defer c.RUnlock()

	return c.devices[device]
}

// ListDevices lists all cached devices by qualified name.
func (c *Cache) ListDevices() []string {
	var devices []string

	c.RLock()
	defer c.RUnlock()

	for name := range c.devices {
		devices = append(devices, name)
	}
	sort.Strings(devices)

	return devices
}

// ListVendors lists all vendors known to the cache.
func (c *Cache) ListVendors() []string {
	var vendors []string

	c.RLock()
	defer c.RUnlock()

	for vendor := range c.specs {
		vendors = append(vendors, vendor)
	}
	sort.Strings(vendors)

	return vendors
}

// ListClasses lists all device classes known to the cache.
func (c *Cache) ListClasses() []string {
	var (
		cmap    = map[string]struct{}{}
		classes []string
	)

	c.RLock()
	defer c.RUnlock()

	for _, specs := range c.specs {
		for _, spec := range specs {
			cmap[spec.GetClass()] = struct{}{}
		}
	}
	for class := range cmap {
		classes = append(classes, class)
	}
	sort.Strings(classes)

	return classes
}

// GetVendorSpecs returns all specs for the given vendor.
func (c *Cache) GetVendorSpecs(vendor string) []*Spec {
	c.RLock()
	defer c.RUnlock()

	return c.specs[vendor]
}

// GetSpecErrors returns all errors encountered for the spec during the
// last cache refresh.
func (c *Cache) GetSpecErrors(spec *Spec) []error {
	return c.errors[spec.GetPath()]
}

// GetErrors returns all errors encountered during the last
// cache refresh.
func (c *Cache) GetErrors() map[string][]error {
	c.RLock()
	defer c.RUnlock()

	errors := make(map[string][]error)
	for spec, err := range c.errors {
		errors[spec] = err
	}
	for dir, err := range c.dirErrors {
		errors[dir] = []error{err}
	}
	return errors
}

// GetSpecDirectories returns the CDI Spec directories currently in use.
func (c *Cache) GetSpecDirectories() []string {
	c.RLock()
	defer c.RUnlock()

	dirs := make([]string, len(c.specDirs))
	copy(dirs, c.specDirs)
	return dirs
}

// GetSpecDirErrors returns any errors related to configured Spec directories.
func (c *Cache) GetSpecDirErrors() map[string]error {
	c.RLock()
	defer c.RUnlock()

	if c.dirErrors == nil {
		return nil
	}
	errors := make(map[string]error)
	for dir, err := range c.dirErrors {
		errors[dir] = err
	}
	return errors
}

// Create any missing ones among the requested directories.
func (c *Cache) createMissingDirs() {
	var (
		dir string
		err error
	)
	for _, dir = range c.specDirs {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			c.dirErrors[dir] = errors.Wrap(err, "failed to create directory")
		}
	}
}

// Our fsnotify helper wrapper.
type watch struct {
	w *fsnotify.Watcher
}

// Set up monitoring for the given Spec directories.
func (w *watch) setup(dirs []string, dirErrors map[string]error) ([]string, error) {
	var (
		used []string
		dir  string
		err  error
	)

	w.w, err = fsnotify.NewWatcher()
	if err != nil {
		for _, dir = range dirs {
			dirErrors[dir] = errors.Wrap(err, "failed to create watcher")
		}
		return nil, err
	}

	for _, dir = range dirs {
		err = w.w.Add(dir)
		if err != nil && dirErrors[dir] == nil {
			dirErrors[dir] = errors.Wrap(err, "failed to monitor for changes")
		} else {
			used = append(used, dir)
		}
	}

	return used, nil
}

// Start watching a set of directories for relevant changes.
func (w *watch) start(m *sync.RWMutex, refresh func() error) {
	go w.watch(m, refresh)
}

// Stop watching directories.
func (w *watch) stop() {
	if w.w != nil {
		w.w.Close()
	}
}

// Watch Spec directory changes, triggering a refresh if necessary.
func (w *watch) watch(m *sync.RWMutex, refresh func() error) {
	watch := w.w
	for {
		select {
		case event, ok := <-watch.Events:
			if !ok {
				return
			}

			if (event.Op & (fsnotify.Rename | fsnotify.Remove | fsnotify.Write)) == 0 {
				continue
			}
			if event.Op == fsnotify.Write {
				if ext := filepath.Ext(event.Name); ext != ".json" && ext != ".yaml" {
					continue
				}
			}

			m.Lock()
			refresh()
			m.Unlock()

		case _, ok := <-watch.Errors:
			if !ok {
				return
			}
		}
	}
}
