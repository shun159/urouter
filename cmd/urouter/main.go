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

package main

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf/rlimit"
	"github.com/shun159/urouter/internal"
	"github.com/shun159/urouter/pkg/config"
	"github.com/shun159/urouter/pkg/coreelf"
	"github.com/shun159/urouter/pkg/maps/tx_ports"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("%+v", err)
	}

	if err := coreelf.Init(); err != nil {
		log.Fatalf("%+v", err)
	}

	if err := tx_ports.InitTxPorts(); err != nil {
		log.Fatalf("%+v", err)
	}

	ports := []config.TxPorts{
		{IfName: "veth1"},
		{IfName: "veth3"},
		{IfName: "veth5"},
		{IfName: "veth7"},
	}

	if err := config.SetTxPorts(ports); err != nil {
		log.Fatalf("%+v", err)
	}

	var vk uint32
	var vv uint32

	tx_ports_iter := tx_ports.Iter()
	for tx_ports_iter.Next(&vk, &vv) {
		fmt.Printf("vif k: %+v  v: %+v\n", vk, vv)
	}

	if err := internal.App(); err != nil {
		log.Fatalf("%+v", err)
	}
}
