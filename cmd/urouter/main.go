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

	"github.com/shun159/urouter/internal"
	"github.com/shun159/urouter/pkg/config"
	"github.com/shun159/urouter/pkg/maps/domainmap"
	"github.com/shun159/urouter/pkg/maps/vifmap"
)

func main() {
	if err := domainmap.InitDomainMaps(1000); err != nil {
		log.Fatalf("%+v", err)
	}

	if err := vifmap.InitVifMap(100); err != nil {
		log.Fatalf("%+v", err)
	}

	domains := []config.DomainConfig{
		{DomainId: 1},
		{DomainId: 2},
	}

	vifs := []config.VifConfig{
		{IfName: "veth1", DomainId: 1},
		{IfName: "veth3", DomainId: 1},
		{IfName: "veth5", DomainId: 2},
		{IfName: "veth7", DomainId: 2},
	}

	if err := config.SetDomains(domains); err != nil {
		log.Fatalf("%+v", err)
	}

	if err := config.SetVifs(vifs); err != nil {
		log.Fatalf("%+v", err)
	}

	devmap_iter, err := domainmap.GetDevmapIterFromDomainId(1)
	if err != nil {
		log.Fatalf("%+v", err)
	}

	var k domainmap.DomainInnerKey
	var v domainmap.DomainInnerVal

	for devmap_iter.Next(&k, &v) {
		fmt.Printf("k: %+v  v: %+v\n", k, v)
	}

	var vk vifmap.VifKey
	var vv vifmap.VifVal

	vif_iter := vifmap.IterVif()
	for vif_iter.Next(&vk, &vv) {
		fmt.Printf("k: %+v  v: %+v\n", vk, vv)
	}

	if err := internal.App(); err != nil {
		log.Fatalf("%+v", err)
	}
}
