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

package tx_ports

import (
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/shun159/urouter/pkg/coreelf"
)

var txPortsMap *coreelf.TxPorts

// InitTxPorts inits the tx_ports map
func InitTxPorts() error {
	m, err := coreelf.NewTxPorts()
	if err != nil {
		return errors.WithStack(err)
	}

	txPortsMap = m
	return nil
}

// AddTxPort updates the list of the devmap for the redirection
func AddTxPort(ifindex uint32) error {
	if txPortsMap == nil {
		return errors.New("the map is not initialized yet")
	}

	return txPortsMap.Map.Update(&ifindex, &ifindex, 0)
}

// GetTxPortsIter returns the iterator of the tx_ports map
func Iter() *ebpf.MapIterator {
	return txPortsMap.Map.Iterate()
}
