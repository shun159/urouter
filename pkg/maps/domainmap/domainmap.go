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
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

const DomainMapName = "domain_map"
const DomainMapMaxEntries = 100

var (
	domainOuterMap *DomainOuterMap
)

/*
 * InitDomainMaps inits the inner/outer maps.
 */
func InitDomainMaps(tableSize uint32) error {
	innerMapSpec := newDomainInnerMapSpec(1000)
	outer, err := NewDomainOuterMap(DomainMapName, DomainMapMaxEntries, 100, innerMapSpec)
	if err != nil {
		return err
	}
	domainOuterMap = outer
	return nil
}

// AddDomainTable adds a domain table with empty map
func AddDomainTable(domain_id uint32) error {
	outer := domainOuterMap
	if outer == nil {
		return errors.New("outer domain map not yet initialized")
	}

	inner, err := createDomainInnerMap(100)
	if err != nil {
		return err
	}
	return outer.UpdateDomain(domain_id, inner)
}

/*
 * updateDomainTable creates a new inner Domain Map containing the given domain_id
 * and sets it as the active lookup table for the given domain_id.
 */
func UpdateDomainTable(domain_id uint32, ifindex uint32) error {
	outer := domainOuterMap
	if outer == nil {
		return errors.New("outer domain map not yet initialized")
	}

	var inner *DomainInnerMap
	inner, err := outer.GetDomainDevmap(domain_id)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		// if the domain_id doesn't exist in the outer map, create a new inner.
		t_inner, err := createDomainInnerMap(100)
		if err != nil {
			return err
		}
		inner = t_inner
	} else if err != nil {
		return err
	}

	if err := inner.AddDomainDev(ifindex); err != nil {
		return errors.WithMessage(err, "failed to add netdev to inner map")
	}

	if err := outer.UpdateDomain(domain_id, inner); err != nil {
		return err
	}

	return nil
}

// GetDevmapIterFromDomainId returns iterator object of the devmap containing given domain_id
func GetDevmapIterFromDomainId(domain_id uint32) (*ebpf.MapIterator, error) {
	outer := domainOuterMap
	if outer == nil {
		return nil, errors.New("outer domain map not yet initialized")
	}

	inner, err := outer.GetDomainDevmap(domain_id)
	if err != nil {
		return nil, err
	}

	return inner.Iterate(), nil
}
