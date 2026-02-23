package main

import (
	"log"

	"github.com/lkarlslund/openai-personal-proxy/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
