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
	var inferred bool
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

	if protocol == "" {
		switch port {
		case "80":
			protocol = "http"
			inferred = true
		case "443":
			protocol = "https"
			inferred = true
		case "21":
			protocol = "ftp"
			inferred = true
		case "22":
			protocol = "ssh"
			inferred = true
		case "23":
			protocol = "telnet"
			inferred = true
		case "445":
			protocol = "smb"
			inferred = true
		case "1433":
			protocol = "mssql"
			inferred = true
		case "1521":
			protocol = "oracle"
			inferred = true
		case "3306":
			protocol = "mysql"
			inferred = true
		case "3389":
			protocol = "rdp"
			inferred = true
		case "5432":
			protocol = "postgres"
			inferred = true
		case "5900":
			protocol = "vnc"
			inferred = true
		case "6379":
			protocol = "redis"
			inferred = true
		case "27017":
			protocol = "mongodb"
			inferred = true
		}
	}

	if host == "" || port == "" || protocol == "" {
		op.Log(fmt.Sprintf("跳过目标（字段缺失）：host=%v port=%v protocol=%v", host, port, protocol), "w")
		return nil, nil
	}

	target := fmt.Sprintf("%s:%s", host, port)

	args := []string{"-i", target, "-s", protocol}
	fields := strings.Fields(op.Parameter)
	var filtered []string
	debug := false
	var userFile, passFile string
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "--debug" || fields[i] == "debug" || fields[i] == "debug=true" {
			debug = true
			continue
		}
		if fields[i] == "-U" && i+1 < len(fields) {
			userFile = fields[i+1]
			if !strings.Contains(userFile, "/") {
				userFile = global.DictPath + "/" + userFile
			}
			filtered = append(filtered, "-U", userFile)
			i++
			continue
		}
		if fields[i] == "-P" && i+1 < len(fields) {
			passFile = fields[i+1]
			if !strings.Contains(passFile, "/") {
				passFile = global.DictPath + "/" + passFile
			}
			filtered = append(filtered, "-P", passFile)
			i++
			continue
		}
		filtered = append(filtered, fields[i])
	}
	if len(fields)%2 == 1 {
		last := fields[len(fields)-1]
		if last != "--debug" && last != "debug" && last != "debug=true" {
			filtered = append(filtered, last)
		}
	}
	args = append(args, filtered...)

	if inferred {
		op.Log(fmt.Sprintf("协议推断：%s -> %s（%s）", port, protocol, target), "d")
	}
	cmdStr := strings.Join(append([]string{"/apps/ext/zombie"}, args...), " ")
	op.Log(fmt.Sprintf("执行命令：%s", cmdStr), "d")
	if userFile != "" || passFile != "" {
		op.Log(fmt.Sprintf("使用字典：用户名=%s 密码=%s", userFile, passFile), "d")
	}

	resultCh := make(chan string, 256)
	go utils.Tools.ExecuteCommandToChan("/apps/ext/zombie", args, resultCh)

	var outputBuilder strings.Builder
	found := false
	successLine := ""
	for line := range resultCh {
		if isZombieSuccessLine(line) {
			found = true
			// 优先取包含具体凭据的 [brute] 行
			if strings.HasPrefix(line, "[brute]") {
				successLine = line
			} else if successLine == "" {
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
		if debug {
			out := outputBuilder.String()
			lines := strings.Split(out, "\n")
			head := 0
			if len(lines) > 10 {
				head = 10
			} else {
				head = len(lines)
			}
			op.Log(fmt.Sprintf("输出预览（前 %d 行）：\n%s", head, strings.Join(lines[:head], "\n")), "d")
		}
		matched := successLine
		if matched != "" {
			matched = parseZombieSuccess(matched)
		}
		op.ResultFunc(types.VulnResult{
			Url:      url,
			VulnId:   op.PluginId,
			VulName:  fmt.Sprintf("%s 弱口令", strings.ToUpper(protocol)),
			Matched:  matched,
			Level:    "high",
			Request:  strings.Join(append([]string{"/apps/ext/zombie"}, args...), " "),
			Response: outputBuilder.String(),
			TaskName: op.TaskName,
			Status:   1,
		})
		op.Log(fmt.Sprintf("发现弱口令：%s（%s）", target, protocol), "w")
	} else {
		op.Log(fmt.Sprintf("未发现弱口令：%s（%s）", target, protocol), "i")
	}

	return nil, nil
}

func parseZombieSuccess(line string) string {
	raw := line
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[brute]") {
		return "登录成功：" + raw
	}
	parts := strings.Fields(line)
	// Expected: [brute] url user pass, msg...
	if len(parts) < 3 {
		return "登录成功：" + raw
	}

	// Find the part ending with comma
	endIdx := -1
	for i := 2; i < len(parts); i++ {
		if strings.HasSuffix(parts[i], ",") {
			endIdx = i
			break
		}
	}

	if endIdx == -1 {
		return "登录成功：" + raw
	}

	// Remove the comma
	parts[endIdx] = strings.TrimSuffix(parts[endIdx], ",")
	creds := parts[2 : endIdx+1]

	if len(creds) == 1 {
		// Single credential
		return fmt.Sprintf("凭据: %s (原始信息: %s)", creds[0], raw)
	} else if len(creds) >= 2 {
		// User and Password
		user := creds[0]
		pass := strings.Join(creds[1:], " ")
		return fmt.Sprintf("账号: %s | 密码: %s (原始信息: %s)", user, pass, raw)
	}

	return "登录成功：" + raw
}

func isZombieSuccessLine(line string) bool {
	l := strings.ToLower(line)
	if strings.Contains(l, "login successfully") {
		return true
	}
	if strings.Contains(l, "success") && !strings.Contains(l, "unsuccess") && !strings.Contains(l, "fail") {
		return true
	}
	return false
}
