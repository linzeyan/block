package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/linzeyan/block"
	"github.com/linzeyan/block/log"
)

const (
	usage = `Block IP by iptables

Usage: block [option]

Options:
`
)

var (
	option  = flag.String("o", "in", "Specify Block in/out bound traffic or log")
	action  = flag.String("a", "insert", "Specify insert/append/delete/clear/list rule")
	ip      = flag.String("ip", "", "Specify IP or CIDRs")
	logFile = flag.String("f", "", "Specify log file")
	limit   = flag.Int("limit", 100, "Limit requests per minute")
)

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	switch *action {
	case "clear", "list":
		var c bool
		if *action == "clear" {
			c = true
		}
		resp, ok := block.ListRules(*option, c)
		if ok {
			for i := range resp {
				fmt.Println(resp[i])
			}
		}
	case "insert", "append", "delete":
		switch *option {
		case "in":
			if *ip != "" {
				block.BlockInbound(*action, *ip)
			} else {
				printUsage()
			}
		case "out":
			if *ip != "" {
				block.BlockOutbound(*action, *ip)
			} else {
				printUsage()
			}
		case "log":
			if *logFile != "" {
				log.Limit = *limit
				resp := log.GrepLog(*logFile)
				for i := range resp {
					block.BlockInbound(*action, resp[i])
				}
			} else {
				printUsage()
			}
		default:
			printUsage()
		}
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Print(usage)
	flag.PrintDefaults()
}
