package internal

import (
	"time"

	"github.com/pkg/errors"
	"github.com/shun159/urouter/pkg/coreelf"
)

func App() error {
	objs := coreelf.UrouterObjs()
	if err := objs.LoadProg(); err != nil {
		return errors.WithStack(err)
	}
	defer objs.Close()

	l, err := objs.AttachDev("wlan0")
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
