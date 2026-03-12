
package plugin

import (
	"fmt"
	"strings"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/global"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/options"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/types"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/utils"
)

func GetName() string {
	return "zombie-scan"
}

func Install() error {
	return nil
}

func Check() error {
	return nil
}

func Uninstall() error {
	return nil
}

func Execute(input interface{}, op options.PluginOption) (interface{}, error) {
	var ip, port, protocol string
	if asset, ok := input.(types.AssetHttp); ok {
		ip = asset.Ip
		port = asset.Port
		protocol = asset.Protocol
	} else if assetOther, ok := input.(types.AssetOther); ok {
		ip = assetOther.Ip
		port = assetOther.Port
		protocol = assetOther.Protocol
	} else {
		return nil, fmt.Errorf("invalid input type")
	}

	target := fmt.Sprintf("%s:%s", ip, port)

	args := []string{"-i", target, "-s", protocol}
	fields := strings.Fields(op.Parameter)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-U" || fields[i] == "-P" {
			fields[i+1] = global.DictPath + "/" + fields[i+1]
		}
	}
	args = append(args, fields...)

	resultCh := make(chan string, 256)
	go utils.Tools.ExecuteCommandToChan("/apps/ext/zombie", args, resultCh)

	var outputBuilder strings.Builder
	found := false
	for line := range resultCh {
		if strings.Contains(line, "Success") {
			found = true
		}
		if outputBuilder.Len() < 1024*1024 {
			outputBuilder.WriteString(line)
			outputBuilder.WriteByte('\n')
		}
	}

	if found {
		vuln := types.VulnResult{
			TaskName:   op.TaskName,
			Plugin:     op.Name,
			Target:     target,
			VulnName:   "弱口令漏洞",
			VulnDetail: outputBuilder.String(),
			VulnLevel:  "高危",
		}
		op.ResultFunc(vuln)
		op.Log(fmt.Sprintf("发现弱口令: %s", target), "w")
	}

	return nil, nil
}
