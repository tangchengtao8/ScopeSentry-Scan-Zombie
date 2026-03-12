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
	var host, port, protocol string
	if asset, ok := input.(types.AssetHttp); ok {
		host = asset.IP
		if host == "" {
			host = asset.Host
		}
		port = asset.Port
		protocol = asset.Service
	} else if assetOther, ok := input.(types.AssetOther); ok {
		host = assetOther.IP
		if host == "" {
			host = assetOther.Host
		}
		port = assetOther.Port
		protocol = assetOther.Service
	} else {
		return nil, fmt.Errorf("invalid input type")
	}

	if host == "" || port == "" || protocol == "" {
		return nil, nil
	}

	target := fmt.Sprintf("%s:%s", host, port)

	args := []string{"-i", target, "-s", protocol}
	fields := strings.Fields(op.Parameter)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "-U" || fields[i] == "-P" {
			if !strings.Contains(fields[i+1], "/") {
				fields[i+1] = global.DictPath + "/" + fields[i+1]
			}
		}
	}
	args = append(args, fields...)

	resultCh := make(chan string, 256)
	go utils.Tools.ExecuteCommandToChan("/apps/ext/zombie", args, resultCh)

	var outputBuilder strings.Builder
	found := false
	successLine := ""
	for line := range resultCh {
		if strings.Contains(line, "Success") {
			found = true
			if successLine == "" {
				successLine = line
			}
		}
		if outputBuilder.Len() < 1024*1024 {
			outputBuilder.WriteString(line)
			outputBuilder.WriteByte('\n')
		}
	}

	if found {
		url := target
		if protocol == "http" || protocol == "https" {
			url = fmt.Sprintf("%s://%s", protocol, target)
		}
		op.ResultFunc(types.VulnResult{
			Url:      url,
			VulnId:   op.PluginId,
			VulName:  "Weak Password",
			Matched:  successLine,
			Level:    "high",
			Request:  strings.Join(append([]string{"/apps/ext/zombie"}, args...), " "),
			Response: outputBuilder.String(),
			TaskName: op.TaskName,
			Status:   1,
		})
		op.Log(fmt.Sprintf("发现弱口令: %s", target), "w")
	}

	return nil, nil
}
