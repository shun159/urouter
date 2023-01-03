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

package domain

import (
	"unsafe"

	"github.com/cilium/ebpf"
)

// DomainInnerMap represents a domain inner map
type DomainInnerMap ebpf.Map

// DomainInnerKey is the key of a maglev inner map.
type DomainInnerKey struct {
	Index uint32
}

// DomainInnerVal is the value of a maglev inner map.
type DomainInnerVal struct {
	Ifindex uint32
}

// DomainInnerMapFromID returns a new object representing the domain inner map
// identified by an ID
func DomainInnerMapFromID(id uint32) (*DomainInnerMap, error) {
	m, err := ebpf.NewMapFromFD(int(id))
	if err != nil {
		return nil, err
	}

	return (*DomainInnerMap)(m), nil
}

// newDomainInnerMapSpec returns the spec for domain inner map.
func newDomainInnerMapSpec(maxEntries uint32) *ebpf.MapSpec {
	return &ebpf.MapSpec{
		Name:       "urouter_domain_inner",
		Type:       ebpf.DevMapHash,
		KeySize:    uint32(unsafe.Sizeof(DomainInnerKey{})),
		ValueSize:  uint32(unsafe.Sizeof(DomainInnerVal{})),
		MaxEntries: maxEntries,
	}
}

func createDomainInnerMap(maxEntries uint32) (*DomainInnerMap, error) {
	spec := newDomainInnerMapSpec(maxEntries)
	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, err
	}
	return (*DomainInnerMap)(m), nil

}
