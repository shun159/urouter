package internal

import (
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/pkg/errors"
	"github.com/shun159/urouter/pkg/coreelf"
)

func App() error {
	objs := coreelf.UrouterObjs()
	if err := objs.LoadProg(); err != nil {
		return errors.WithStack(err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName("wlan0")
	if err != nil {
		return errors.WithStack(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpRouterFn,
		Interface: iface.Index,
	})

	if err != nil {
		return errors.WithStack(err)
	}
	defer l.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
	}

	return nil
}
