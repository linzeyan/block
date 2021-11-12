package block

import (
	"fmt"
	"net"

	"github.com/coreos/go-iptables/iptables"
)

const Table string = "filter"

var Ipt = NewIptables()

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
		err = Ipt.AppendUnique(Table, "INPUT", "-s", ipstr, "-j", "DROP")
	case "insert":
		err = Ipt.Insert(Table, "INPUT", 1, "-s", ipstr, "-j", "DROP")
	case "delete":
		err = Ipt.Delete(Table, "INPUT", "-s", ipstr, "-j", "DROP")
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
		err = Ipt.AppendUnique(Table, "OUTPUT", "-d", ipstr, "-j", "DROP")
	case "insert":
		err = Ipt.Insert(Table, "OUTPUT", 1, "-d", ipstr, "-j", "DROP")
	case "delete":
		err = Ipt.Delete(Table, "OUTPUT", "-d", ipstr, "-j", "DROP")
	default:
		return false
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func ClearRules(opt string) bool {
	var err error
	switch opt {
	case "in":
		err = Ipt.ClearChain(Table, "INPUT")
	case "out":
		err = Ipt.ClearChain(Table, "OUTPUT")
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func ListRules(opt string) ([]string, bool) {
	var err error
	var result []string
	switch opt {
	case "in":
		result, err = Ipt.List(Table, "INPUT")
	case "out":
		result, err = Ipt.List(Table, "OUTPUT")
	}
	if err != nil {
		fmt.Println(err)
		return nil, false
	}
	return result, true

}

func NewIptables() *iptables.IPTables {
	ipt, err := iptables.New()
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return ipt
}
