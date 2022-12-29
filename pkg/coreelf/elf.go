package coreelf

import (
	"github.com/pkg/errors"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS urouter ../../bpf/xdp_kern.bpf.c

func UrouterObjs() urouterObjects {
	return urouterObjects{}
}

func (obj *urouterObjects) LoadProg() error {
	if err := loadUrouterObjects(obj, nil); err != nil {
		return errors.WithStack(err)
	}
	return nil
}
