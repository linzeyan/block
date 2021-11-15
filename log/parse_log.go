package log

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/tomwright/dasel"
)

const (
	// TimeStamp: T09:45:38+08:00
	TimeFormat string = "15:04:"
)

var (
	Limit   int    = 100
	WorkDir string = "/nginx/logs"
)

func GrepLog(file string) []string {
	ctx := context.Background()
	target := fmt.Sprintf(`%s%s`, "T", time.Now().Add(-1*time.Minute).Local().Format(TimeFormat))
	cmd := exec.CommandContext(ctx, "grep", target, file)
	cmd.Dir = WorkDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return parseLog(output)
}

func parseLog(content []byte) (ips []string) {
	var temp interface{}
	var data []interface{}
	dec := json.NewDecoder(bytes.NewReader(content))
	for {
		// err = json.Unmarshal(f, &temp)
		err := dec.Decode(&temp)
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println(err)
			return
		}
		data = append(data, temp)
	}
	rootNode := dasel.New(data)
	selector, err := rootNode.QueryMultiple(".[*].client")
	if err != nil {
		fmt.Println(err)
		return
	}
	var m = make(map[string]int)
	for _, n := range selector {
		ip := fmt.Sprint(n.InterfaceValue())
		if _, ok := m[ip]; ok {
			m[ip]++
		}
		m[ip] = 1
	}
	for k, v := range m {
		if v >= Limit {
			ips = append(ips, k)
		}
	}
	return
}
