
package plugin

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/options"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/types"
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

	// 构造命令：调用 /apps/ext/zombie
	// zombie -i 1.2.3.4:80 -s http --user admin --pass admin
	target := fmt.Sprintf("%s:%s", ip, port)
	
	// 使用 op.Parameter，它已经包含了前端传来的参数
	// 假设用户填写的参数是 -U users.txt -P passwords.txt
	args := []string{"-i", target, "-s", protocol}
	if op.Parameter != "" {
		args = append(args, strings.Fields(op.Parameter)...)
	}

	cmd := exec.Command("/apps/ext/zombie", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 即使报错也解析输出，因为 zombie 可能因为发现弱口令而退出码非0
		op.Log(fmt.Sprintf("Zombie 运行出错: %v, 输出: %s", err, string(output)), "e")
	}

	resultStr := string(output)
	if strings.Contains(resultStr, "Success") {
		vuln := types.VulnResult{
			TaskName:   op.TaskName,
			Plugin:     op.Name,
			Target:     target,
			VulnName:   "弱口令漏洞",
			VulnDetail: resultStr,
			VulnLevel:  "高危",
		}
		op.ResultFunc(vuln)
		op.Log(fmt.Sprintf("发现弱口令: %s", target), "w")
	}

	return nil, nil
}
