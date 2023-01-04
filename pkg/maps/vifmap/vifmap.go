/* Copyright (C) 2022-present, Eishun Kondoh <dreamdiagnosis@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU GPL as published by
 * the FSF; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package vifmap

import (
	"unsafe"

	"github.com/cilium/ebpf"
)

// VifKey is the key of vif map
type VifKey struct {
	Ifindex uint32
}

// Vifval is the configuration of the vif
type VifVal struct {
	DomainId uint32
}

// VifMap represents a vif map
type VifMap struct {
	*ebpf.Map
}

var vifMap *VifMap

// InitVifMap inits the vif map.
func InitVifMap(tableSize uint32) error {
	m, err := createVifMap(tableSize)
	if err != nil {
		return err
	}
	vifMap = m
	return nil
}

// AddVif puts VifVal conrrensponding the key onto the hash map
func AddVif(ifindex uint32, vifval *VifVal) error {
	key := VifKey{ifindex}
	return vifMap.Map.Put(&key, vifval)
}

// IterVif returns an iterator of the hash map.
func IterVif() *ebpf.MapIterator {
	return vifMap.Iterate()
}

// newVifMapSpec retruns the spec for vif map.
func newVifMapSpec(maxEntries uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "urouter_vif",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(VifKey{})),
		ValueSize:  uint32(unsafe.Sizeof(VifVal{})),
		MaxEntries: maxEntries,
	}
}

func createVifMap(maxEntries uint32) (*VifMap, error) {
	spec := newVifMapSpec(maxEntries)
	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, err
	}
	return &VifMap{m}, nil
}
