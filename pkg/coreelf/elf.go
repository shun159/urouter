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

package coreelf

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS urouter ../../bpf/urouter.bpf.c -- -Wno-compare-distinct-pointer-types -Wno-int-conversion -Wnull-character -g -c -O2 -D__KERNEL__

var maps *urouterMaps
var programs *urouterPrograms

func Init() error {
	obj := urouterObjects{}
	if err := loadUrouterObjects(&obj, nil); err != nil {
		fmt.Println(err)
		return errors.WithStack(err)
	}
	maps = &obj.urouterMaps
	programs = &obj.urouterPrograms

	return nil
}

// Definitions for TxPorts

type TxPorts struct {
	*ebpf.Map
}

// NewTxPorts returns a new object representing a tx_ports
func NewTxPorts() (*TxPorts, error) {
	if maps == nil {
		return nil, errors.New("maps are not initialized yet.")
	}
	return &TxPorts{maps.TxPorts}, nil
}

// Definitions for BridgeTable

type BridgeTable struct {
	*ebpf.Map
}

// NewBridgeTable returns a new object representing a bridge_table
func NewBridgeTable() (*BridgeTable, error) {
	if maps == nil {
		return nil, errors.New("maps are not initialized yet.")
	}
	return &BridgeTable{maps.BridgeTable}, nil
}

// Definitions for VifTable
type VifTable struct {
	*ebpf.Map
}

// NewVifTable returns a new object representing a vif_table
func NewVifTable() (*VifTable, error) {
	if maps == nil {
		return nil, errors.New("maps are not initialized yet.")
	}
	return &VifTable{maps.VifTable}, nil
}

// Definitions for all maps

func GetUrouterMaps() (*urouterMaps, error) {
	if maps == nil {
		return nil, errors.New("maps not yet initialized")
	}
	return maps, nil
}

// Definitions for all programs

func GetUrouterPrograms() (*urouterPrograms, error) {
	if programs == nil {
		return nil, errors.New("maps not yet initialized")
	}
	return programs, nil
}

func (obj *urouterPrograms) AttachDev(dev_list []string) ([]link.Link, error) {
	var links []link.Link

	for _, dev := range dev_list {
		iface, err := net.InterfaceByName(dev)
		if err != nil {
			return []link.Link{}, errors.WithStack(err)
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   obj.XdpRouterFn,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})

		if err != nil {
			return []link.Link{}, errors.WithStack(err)
		}

		links = append(links, l)
	}
	return links, nil
}
