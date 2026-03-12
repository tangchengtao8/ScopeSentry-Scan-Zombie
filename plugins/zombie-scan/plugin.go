
package plugin

import (
	"fmt"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/options"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/types"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/utils"
	"github.com/chainreactors/zombie/core"
	"github.com/chainreactors/zombie/pkg"
)

func GetName() string {
	return "zombie-scan"
}

func Install() error {
	// 加载 zombie 插件库
	return pkg.Load()
}

func Check() error {
	return nil
}

func Uninstall() error {
	return nil
}

func Execute(input interface{}, op options.PluginOption) (interface{}, error) {
	// 获取资产信息
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

	// 从前端传递的参数中解析用户和密码字典路径
	args, err := utils.Tools.ParseArgs(op.Parameter, "U", "P")
	if err != nil {
		op.Log(fmt.Sprintf("解析参数失败: %v", err), "e")
	}

	zombieOpt := core.Option{}
	zombieOpt.IP = []string{fmt.Sprintf("%s:%s", ip, port)}
	zombieOpt.ServiceName = protocol
	
	// 如果参数中有指定字典文件，则使用它
	if u, ok := args["U"]; ok && u != "" {
		zombieOpt.UsernameFile = u
	}
	if p, ok := args["P"]; ok && p != "" {
		zombieOpt.PasswordFile = p
	}

	// 验证配置
	if err := zombieOpt.Validate(); err != nil {
		return nil, err
	}

	// 准备执行器
	runner, err := zombieOpt.Prepare()
	if err != nil {
		return nil, err
	}

	// 捕获爆破结果并上报
	go func() {
		for result := range runner.OutputCh {
			if result.OK {
				vuln := types.VulnResult{
					TaskName:   op.TaskName,
					Plugin:     op.Name,
					Target:     result.URI(),
					VulnName:   "弱口令漏洞",
					VulnDetail: fmt.Sprintf("发现弱口令! 协议: %s, 账号: %s, 密码: %s", result.Service, result.Username, result.Password),
					VulnLevel:  "高危",
				}
				// 上报漏洞结果到前端
				op.ResultFunc(vuln)
				op.Log(fmt.Sprintf("发现弱口令: %s", result.URI()), "w")
			}
		}
	}()

	// 开始执行爆破
	runner.Run()

	return nil, nil
}
