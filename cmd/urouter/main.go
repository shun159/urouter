package main

import (
	"log"

	"github.com/shun159/urouter/internal"
)

func main() {
	err := internal.App()
	if err != nil {
		log.Fatalf("%+v", err)
	}
}
