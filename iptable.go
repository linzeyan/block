package block

import (
	"fmt"
	"net"

	"github.com/coreos/go-iptables/iptables"
)

var iptable, _ = iptables.New()

func parseIP(s string) (ip string) {
	if net.ParseIP(s) != nil {
		ip = fmt.Sprintf("%s%s", s, "/32")
	} else if _, cidr, _ := net.ParseCIDR(s); cidr != nil {
		ip = cidr.String()
	}
	return
}

/* opt: append, insert, delete */
func BlockInbound(opt, ip string) bool {
	ipstr := parseIP(ip)
	var err error
	switch opt {
	case "append":
		err = iptable.Append("filter", "INPUT", "-s", ipstr, "-j", "DROP")
	case "insert":
		err = iptable.Insert("filter", "INPUT", 1, "-s", ipstr, "-j", "DROP")
	case "delete":
		err = iptable.Delete("filter", "INPUT", "-s", ipstr, "-j", "DROP")
	default:
		return false
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

/* opt: append, insert, delete */
func BlockOutbound(opt, ip string) bool {
	ipstr := parseIP(ip)
	var err error
	switch opt {
	case "append":
		err = iptable.Append("filter", "OUTPUT", "-s", ipstr, "-j", "DROP")
	case "insert":
		err = iptable.Insert("filter", "OUTPUT", 1, "-s", ipstr, "-j", "DROP")
	case "delete":
		err = iptable.Delete("filter", "OUTPUT", "-s", ipstr, "-j", "DROP")
	default:
		return false
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}
