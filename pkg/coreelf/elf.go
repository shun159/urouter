package coreelf

import (
	"fmt"
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

func (obj *urouterObjects) AttachDev(dev string) (link.Link, error) {
	iface, err := net.InterfaceByName(dev)
	fmt.Println(iface)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   obj.XdpRouterFn,
		Interface: iface.Index,
	})

	if err != nil {
		return nil, errors.WithStack(err)
	}

	return l, nil
}
