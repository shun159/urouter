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
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS urouter ../../bpf/urouter.bpf.c -- -Wno-compare-distinct-pointer-types  -Wnull-character -g -c -O2 -D__KERNEL__

func UrouterObjs() urouterObjects {
	return urouterObjects{}
}

func (obj *urouterObjects) LoadProg() error {
	if err := loadUrouterObjects(obj, nil); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (obj *urouterObjects) AttachDev(dev_list []string) ([]link.Link, error) {
	var links []link.Link

	for _, dev := range dev_list {
		iface, err := net.InterfaceByName(dev)
		if err != nil {
			return []link.Link{}, errors.WithStack(err)
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   obj.XdpRouterFn,
			Interface: iface.Index,
		})

		if err != nil {
			return []link.Link{}, errors.WithStack(err)
		}

		links = append(links, l)
	}
	return links, nil
}
