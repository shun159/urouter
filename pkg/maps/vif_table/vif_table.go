/*
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

package vif_table

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/shun159/urouter/pkg/coreelf"
)

var vifTableMap *coreelf.VifTable

type Entry struct {
	VifType uint32
	Mac     [6]uint8
	Ip4     uint32
	Ip6u    uint64
	Ip6l    uint64
}

const (
	UR_VIF_DOWNLINK uint32 = 0
	UR_VIF_UPLINK   uint32 = 1
	UR_VIF_IRB      uint32 = 2
)

func InitVifTable() error {
	m, err := coreelf.NewVifTable()
	if err != nil {
		return errors.WithStack(err)
	}

	vifTableMap = m
	return nil
}

func AddEntry(ifindex uint32, vif_type uint32) error {
	if vifTableMap == nil {
		return errors.New("the map is not initialized yet")
	}

	entry := &Entry{
		VifType: vif_type,
		Mac:     [6]uint8{},
		Ip4:     0,
		Ip6u:    0,
		Ip6l:    0,
	}
	fmt.Printf("%+v\n", entry)
	return vifTableMap.Map.Put(&ifindex, entry)
}

func Iter() *ebpf.MapIterator {
	return vifTableMap.Map.Iterate()
}
