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

package config

import (
	"net"

	"github.com/pkg/errors"
	"github.com/shun159/urouter/pkg/maps/tx_ports"
	"github.com/shun159/urouter/pkg/maps/vif_table"
)

type Vif struct {
	IfName  string
	VifType uint32
}

type TxPorts struct {
	IfName string
}

func SetTxPorts(ports []TxPorts) error {
	for _, port := range ports {
		iface, err := net.InterfaceByName(port.IfName)
		if err != nil {
			return errors.WithStack(err)
		}

		ifindex := uint32(iface.Index)
		if err := tx_ports.AddTxPort(ifindex); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func SetVif(ports []Vif) error {
	for _, port := range ports {
		iface, err := net.InterfaceByName(port.IfName)
		if err != nil {
			return errors.WithStack(err)
		}

		ifindex := uint32(iface.Index)
		if err := vif_table.AddEntry(ifindex, port.VifType); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
