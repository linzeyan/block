package block

import (
	"fmt"
	"net"
	"strings"

	"github.com/coreos/go-iptables/iptables"
)

const Table string = "filter"

/* action: append, insert, delete */
func BlockInbound(opt, ip string) bool {
	var ipt, ipstr = NewIptables(ip)
	var err error
	switch opt {
	case "append":
		err = ipt.AppendUnique(Table, "INPUT", "-s", ipstr, "-j", "DROP")
	case "insert":
		err = ipt.Insert(Table, "INPUT", 1, "-s", ipstr, "-j", "DROP")
	case "delete":
		err = ipt.DeleteIfExists(Table, "INPUT", "-s", ipstr, "-j", "DROP")
	default:
		return false
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

/* action: append, insert, delete */
func BlockOutbound(opt, ip string) bool {
	var ipt, ipstr = NewIptables(ip)
	var err error
	switch opt {
	case "append":
		err = ipt.AppendUnique(Table, "OUTPUT", "-d", ipstr, "-j", "DROP")
	case "insert":
		err = ipt.Insert(Table, "OUTPUT", 1, "-d", ipstr, "-j", "DROP")
	case "delete":
		err = ipt.DeleteIfExists(Table, "OUTPUT", "-d", ipstr, "-j", "DROP")
	default:
		return false
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

/* action: list, clear */
func ListRules(opt string, clear bool) ([]string, bool) {
	var result []string = []string{"IPv4"}
	/* IPv4 */
	var ipt, err = iptables.New()
	if err != nil {
		fmt.Println(err)
		return result, false
	}
	temp, _ := clearAndList(ipt, opt, clear)
	for i := range temp {
		result = append(result, temp[i])
	}
	/* IPv6 */
	ipt, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		fmt.Println(err)
		return result, false
	}
	result = append(result, "IPv6")
	temp, _ = clearAndList(ipt, opt, clear)
	for i := range temp {
		result = append(result, temp[i])
	}
	return result, true
}

func clearAndList(ipt *iptables.IPTables, opt string, clear bool) ([]string, bool) {
	var err error
	var chain string = "INPUT"
	if opt == "out" {
		chain = "OUTPUT"
	}
	if clear {
		err = ipt.ClearChain(Table, chain)
		if err != nil {
			fmt.Println(err)
			return nil, false
		}
	}

	var result []string
	result, err = ipt.List(Table, chain)
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
