package main

import (
	"fmt"
	"log"

	"github.com/shun159/urouter/internal"
	"github.com/shun159/urouter/pkg/maps/domainmap"
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

	if err := internal.App(); err != nil {
		log.Fatalf("%+v", err)
	}
}
