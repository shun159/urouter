package coreelf

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS urouter ../../bpf/xdp_kern.bpf.c

func (obj *urouterObjects) LoadProg() error {
	if err := loadUrouterObjects(&obj, nil); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (obj *urouterObjects) Attach(devname string) (*link.Link, error) {
	iface, err := net.InterfaceByName(devname)
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

func ReadCollection() (*urouterObjects, error) {
	spec, err := loadUrouter()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// TODO: BPF log level remove hardcoding. yaml in config
	obj, err := spec.Load(
		&ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogLevel: 2,
				LogSize:  102400 * 1024,
			},
		},
	)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return obj, nil
}
