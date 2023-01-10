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

package bridge_table

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/shun159/urouter/pkg/coreelf"
)

var bridgeTableMap *coreelf.BridgeTable

// Entry
type Entry struct {
	MacAddress [6]uint8
	PortNo     uint32
}

// InitBridgeTable initializes the bridge_table
func InitBridgeTable() error {
	m, err := coreelf.NewBridgeTable()
	if err != nil {
		return errors.WithStack(err)
	}

	bridgeTableMap = m
	return nil
}

// GetAllEntry returns all entry of the bridge_table
func GetAllEntry() []Entry {
	ret := []Entry{}
	var mac_addr [6]uint8
	var port_no uint32

	iter := Iter()
	for iter.Next(&mac_addr, &port_no) {
		ret = append(ret, Entry{mac_addr, port_no})
	}

	return ret
}

// Iter returns an iterator of the bridge_table mpa
func Iter() *ebpf.MapIterator {
	return bridgeTableMap.Map.Iterate()
}
