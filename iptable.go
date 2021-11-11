package block

import (
	"fmt"
	"net"

	"github.com/coreos/go-iptables/iptables"
)

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
	var iptable = NewIptables()
	var err error
	switch opt {
	case "append":
		err = iptable.AppendUnique("filter", "INPUT", "-s", ipstr, "-j", "DROP")
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
	var iptable = NewIptables()
	var err error
	switch opt {
	case "append":
		err = iptable.AppendUnique("filter", "OUTPUT", "-d", ipstr, "-j", "DROP")
	case "insert":
		err = iptable.Insert("filter", "OUTPUT", 1, "-d", ipstr, "-j", "DROP")
	case "delete":
		err = iptable.Delete("filter", "OUTPUT", "-d", ipstr, "-j", "DROP")
	default:
		return false
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func NewIptables() *iptables.IPTables {
	ipt, err := iptables.New()
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return ipt
}
