package internal

import (
	"github.com/pkg/errors"
	"github.com/shun159/urouter/pkg/coreelf"
)

func App() error {
	obj, err := coreelf.ReadCollection()
	if err != nil {
		return errors.WithStack(err)
	}
	defer obj.Close()

	if err := obj.LoadProg(); err != nil {
		return errors.WithStack(err)
	}

	l, err := obj.Attach("wlan0")
	if err != nil {
		return errors.WithStack(err)
	}
	defer l.Close()

	return nil
}
