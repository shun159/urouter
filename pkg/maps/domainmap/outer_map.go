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

package domainmap

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/shun159/urouter/pkg/byteorder"
)

// DomainOuterMap represents a broadcast domains
type DomainOuterMap struct {
	*ebpf.Map
}

// DomainOuterKey is the key of a domain outer map.
type DomainOuterKey struct {
	DomainId uint32
}

// toNetwork converts a domain outer map's key to network byte order
// the key is in network byte order in the eBPF maps.
func (k DomainOuterKey) toNetwork() DomainOuterKey {
	return DomainOuterKey{
		DomainId: byteorder.HostToNetwork32(k.DomainId),
	}
}

// DomainOuterVal is the value of a domain outer map.
type DomainOuterVal struct {
	FD uint32
}

// UpdateDomain sets the given inner map to be the Domain lookup table for the
// devmap with the given Id.
func (m *DomainOuterMap) UpdateDomain(id uint32, inner *DomainInnerMap) error {
	key := DomainOuterKey{DomainId: id}.toNetwork()
	val := DomainOuterVal{FD: uint32(inner.getFD())}
	return m.Map.Update(key, val, 0)
}

// NewDomainOuterMap returns a new object representing a domain outer map.
func NewDomainOuterMap(
	name string,
	maxEntries int,
	tableSize uint32,
	innerMap *ebpf.MapSpec,
) (*DomainOuterMap, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.HashOfMaps,
		KeySize:    uint32(unsafe.Sizeof(DomainOuterKey{})),
		ValueSize:  uint32(unsafe.Sizeof(DomainOuterVal{})),
		MaxEntries: uint32(maxEntries),
		InnerMap:   innerMap,
		Pinning:    ebpf.PinByName,
	})

	if err != nil {
		return nil, err
	}

	return &DomainOuterMap{m}, nil
}

// GetDomainPorts gets the domain port list for the given domain_id
func (m *DomainOuterMap) GetDomainPorts(id uint32) (*DomainInnerMap, error) {
	key := DomainOuterKey{DomainId: id}.toNetwork()
	val := DomainOuterVal{}

	err := m.Lookup(key, &val)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, fmt.Errorf("no domain table entry for domain_id: %v %w", id, err)
	}

	inner, err := DomainInnerMapFromID(val.FD)
	if err != nil {
		return nil, fmt.Errorf("cannot open inner map with id: %d %w", val.FD, err)
	}

	return inner, nil
}
