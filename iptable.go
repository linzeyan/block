package block

import (
	"fmt"
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

const Table string = "filter"

/* opt: append, insert, delete */
func BlockInbound(opt, ip string) bool {
	var ipt, ipstr = NewIptables(ip)
	var err error
	switch opt {
	case "append":
		err = ipt.AppendUnique(Table, "INPUT", "-s", ipstr, "-j", "DROP")
	case "insert":
		err = ipt.Insert(Table, "INPUT", 1, "-s", ipstr, "-j", "DROP")
	case "delete":
		err = ipt.Delete(Table, "INPUT", "-s", ipstr, "-j", "DROP")
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
	var ipt, ipstr = NewIptables(ip)
	var err error
	switch opt {
	case "append":
		err = ipt.AppendUnique(Table, "OUTPUT", "-d", ipstr, "-j", "DROP")
	case "insert":
		err = ipt.Insert(Table, "OUTPUT", 1, "-d", ipstr, "-j", "DROP")
	case "delete":
		err = ipt.Delete(Table, "OUTPUT", "-d", ipstr, "-j", "DROP")
	default:
		return false
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

/* opt: clear */
func ClearRules(opt string) bool {
	var ipt, _ = NewIptables(``)
	var err error
	switch opt {
	case "in":
		err = ipt.ClearChain(Table, "INPUT")
	case "out":
		err = ipt.ClearChain(Table, "OUTPUT")
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

/* opt: list */
func ListRules(opt string) ([]string, bool) {
	var ipt, _ = NewIptables(``)
	var err error
	var result []string
	switch opt {
	case "in":
		result, err = ipt.List(Table, "INPUT")
	case "out":
		result, err = ipt.List(Table, "OUTPUT")
	}
	if err != nil {
		fmt.Println(err)
		return nil, false
	}
	return result, true
}

func NewIptables(s string) (*iptables.IPTables, string) {
	var ip string
	/* Parse IPv6 */
	if i := net.ParseIP(s); i.To4() == nil {
		ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			fmt.Println(err)
			return nil, ""
		}
		ip = strings.TrimSuffix(s, "\n")
		return ipt, ip
	} else if i != nil {
		/* Parse IPv4 */
		ip = strings.TrimSuffix(s, "\n")
	} else if _, cidr, _ := net.ParseCIDR(s); cidr != nil {
		ip = cidr.String()
	}
	ipt, err := iptables.New()
	if err != nil {
		fmt.Println(err)
		return nil, ""
	}
	return ipt, ip
}
