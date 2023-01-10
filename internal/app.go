package internal

import (
	"time"

	"github.com/pkg/errors"
	"github.com/shun159/urouter/pkg/coreelf"
)

func App() error {
	progs, err := coreelf.GetUrouterPrograms()
	if err != nil {
		return errors.WithStack(err)
	}

	links, err := progs.AttachDev([]string{
		"veth1",
		"veth3",
		"veth5",
		"veth7",
	})
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
	}

	return nil
}
