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
	traffic = flag.String("t", "in", "Specify Block in/out bound traffic or log")
	option  = flag.String("o", "insert", "Specify insert/append/delete/clear/list rule")
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

	switch *traffic {
	case "in":
		switch *option {
		case "clear":
			block.ClearRules(*traffic)
		case "list":
			resp, ok := block.ListRules(*traffic)
			if ok {
				for i := range resp {
					fmt.Println(resp[i])
				}
			}
		case "insert", "append", "delete":
			if *ip != "" {
				block.BlockInbound(*option, *ip)
			} else {
				printUsage()
			}
		default:
			printUsage()
		}
	case "out":
		switch *option {
		case "clear":
			block.ClearRules(*traffic)
		case "list":
			resp, ok := block.ListRules(*traffic)
			if ok {
				for i := range resp {
					fmt.Println(resp[i])
				}
			}
		case "insert", "append", "delete":
			if *ip != "" {
				block.BlockOutbound(*option, *ip)
			} else {
				printUsage()
			}
		default:
			printUsage()
		}
	case "log":
		if *logFile != "" {
			log.Limit = *limit
			resp := log.GrepLog(*logFile)
			for i := range resp {
				block.BlockInbound(*option, resp[i])
			}
		} else {
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
