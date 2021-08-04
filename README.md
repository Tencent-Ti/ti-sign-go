## 简介

欢迎使用Ti开发者工具(Tisign)，此工具是Ti平台配套的用于计算http请求签名的开发工具

## 依赖环境
1. Go 1.9版本及以上(如果使用 go mod 需要 Go 1.14)
2. 本工具依赖的SecrectID和SerectKey需在Ti控制平台(管理中心-个人中心-密钥管理)获取，请务必妥善保管
3. 访问平台内部的接口请参考<Ti平台产品白皮书>

## 调用示例

```go
package main

import (
	"fmt"

	"github.com/Tencent-Ti/ti-sign-go/tisign"
)

func main() {
	//以Ti平台 查询用户是否拥有Admin权限 接口为例, 以下是接口的基本信息:
	//   action: DescribeIsAdmin
	//   service: ti-auth
	//   version: 2020-10-10
	//   content-type: application/json
	//   http请求方法: POST
	//   网关访问地址: 127.0.0.1
	headerContent := tisign.HttpHeaderContent{
		XTCAction:   "DescribeIsAdmin",  // 请求接口
		XTCService:  "ti-auth",          // 接口所属服务名
		XTCVersion:  "2020-10-10",       // 接口版本
		ContentType: "application/json", // http请求的content-type, 当前网关只支持: application/json  multipart/form-data
		HttpMethod:  "POST",             // http请求方法，当前网关只支持: POST GET
		Host:        "127.0.0.1",        // 访问网关的host
	}
	// 创建TiSign对象
	ts := tisign.NewTiSign(headerContent, "test-secret-id", "test-secrect-key")
	// 生成通过网关访问后端服务，所需http的请求header 和 签名信息
	HTTPHeaderMap, authorization := ts.CreateSignatureInfo()
	// 打印签名信息
	fmt.Println("============= 签名字符串 Authorization =============")
	fmt.Printf("authorization: %s\n", authorization)
	// 打印http header信息
	fmt.Println("============ 通过网关访问后端服务Http请求头 ============")
	for key, value := range HTTPHeaderMap {
		fmt.Printf("%s: %s\n", key, value)
	}
}
```

## 样例运行步骤
```shell
cd example
make
./ti-sign-example
```

## 签名有效期
**单个签名有效期为60分钟，签名超过60分钟使用会出现签名失败的错误**