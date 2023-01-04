package main

import (
	"fmt"
	"log"

	"github.com/shun159/urouter/internal"
	"github.com/shun159/urouter/pkg/maps/domainmap"
	"github.com/shun159/urouter/pkg/maps/vifmap"
)

func main() {
	if err := domainmap.InitDomainMaps(1000); err != nil {
		log.Fatalf("%+v", err)
	}

	if err := domainmap.UpdateDomainTable(0x11, 3); err != nil {
		log.Fatalf("%+v", err)
	}

	if err := domainmap.UpdateDomainTable(0x11, 5); err != nil {
		log.Fatalf("%+v", err)
	}

	devmap_iter, err := domainmap.GetDevmapIterFromDomainId(0x11)
	if err != nil {
		log.Fatalf("%+v", err)
	}

	var k domainmap.DomainInnerKey
	var v domainmap.DomainInnerVal

	for devmap_iter.Next(&k, &v) {
		fmt.Printf("k: %+v  v: %+v\n", k, v)
	}

	vif, err := vifmap.InitVifMap(100)
	if err != nil {
		log.Fatalf("%+v", err)
	}

	vif.AddVif(3, &vifmap.VifVal{DomainId: 0x11})
	vif.AddVif(5, &vifmap.VifVal{DomainId: 0x11})

	var vk vifmap.VifKey
	var vv vifmap.VifVal

	vif_iter := vif.IterVif()
	for vif_iter.Next(&vk, &vv) {
		fmt.Printf("k: %+v  v: %+v\n", vk, vv)
	}

	if err := internal.App(); err != nil {
		log.Fatalf("%+v", err)
	}
}
