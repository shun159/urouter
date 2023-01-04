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
	"github.com/shun159/urouter/pkg/maps/domainmap"
	"github.com/shun159/urouter/pkg/maps/vifmap"
)

// DomainConfig represents a domain configuration.
// For now the struct include a domain_id only.
type DomainConfig struct {
	DomainId uint32
}

// VifConfig represents the configuration of virtual interface.
// For now, the struct include only a pair of ifname and an id of domain belonging to.
type VifConfig struct {
	IfName   string
	DomainId uint32
}

// SetDomains() puts domains with empty maps.
func SetDomains(domains []DomainConfig) error {
	for _, domain := range domains {
		if err := domainmap.AddDomainTable(domain.DomainId); err != nil {
			return err
		}
	}
	return nil
}

func SetVifs(vifs []VifConfig) error {
	for _, vif := range vifs {
		iface, err := net.InterfaceByName(vif.IfName)
		if err != nil {
			return errors.WithStack(err)
		}

		ifindex := uint32(iface.Index)
		vifval := vifmap.VifVal{DomainId: vif.DomainId}
		if err := vifmap.AddVif(ifindex, &vifval); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}
