package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/linzeyan/block"
)

const (
	usage = `Block IP by iptables

Usage: block [option]

Options:
`
)

var (
	traffic = flag.String("t", "in", "Specify Block in/out bound")
	option  = flag.String("o", "insert", "Specify insert/append/delete rule")
	ip      = flag.String("ip", "", "Specify IP or CIDRs")
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *traffic == "in" && *ip != "" {
		block.BlockInbound(*option, *ip)
	} else if *traffic == "out" && *ip != "" {
		block.BlockOutbound(*option, *ip)
	} else {
		fmt.Print(usage)
		flag.PrintDefaults()
	}
}
