package tisign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

type HttpHeaderContent struct {
	XTCAction    string //请求接口action
	XTCVersion   string //请求接口版本
	XTCService   string //请求接口服务名
	XTCTimestamp string //请求unix时间搓，精确到秒
	Host         string //请求header的host字段
	ContentType  string //http请求Header的Content-type值，当前网关只支持: application/json  multipart/form-data
	HttpMethod   string //http请求方法，只能为 POST 或者 GET
}

type TiSign struct {
	HeaderContent HttpHeaderContent //请求相关的信息
	secretId      string            //Ti平台生成个人签名id
	secretKey     string            //Ti平台生成的个人签名key，非常重要，请不要泄露给他人
}

// 构造TiSign对象
func NewTiSign(headerContent HttpHeaderContent, secretId, secretKey string) *TiSign {
	return &TiSign{
		HeaderContent: headerContent,
		secretId:      secretId,
		secretKey:     secretKey,
	}
}

// 计算sh256签名
func (ts *TiSign) sha256hex(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

// 计算hmac sha256
func (ts *TiSign) hmacsha256(s, key string) string {
	hashed := hmac.New(sha256.New, []byte(key))
	hashed.Write([]byte(s))
	return string(hashed.Sum(nil))
}

// 生成请求网关所必须的http请求header, 并返回header和签名字符串
func (ts *TiSign) CreateSignatureInfo() (map[string]string, string) {
	ts.HeaderContent.XTCTimestamp = strconv.FormatInt(time.Now().Unix(), 10) // 请求unix时间搓，精确到秒
	headers := map[string]string{
		"Host":           ts.HeaderContent.Host,
		"X-TC-Action":    ts.HeaderContent.XTCAction,
		"X-TC-Version":   ts.HeaderContent.XTCVersion,
		"X-TC-Service":   ts.HeaderContent.XTCService,
		"X-TC-Timestamp": ts.HeaderContent.XTCTimestamp,
		"Content-Type":   ts.HeaderContent.ContentType,
	}

	// 1. 构造canonical request 字符串
	// 1.1 设置http请求方法: POST 或 GET
	httpRequestMethod := ts.HeaderContent.HttpMethod
	// 1.2 设置常量URI和QueryString
	canonicalURI := "/"
	canonicalQueryString := ""
	// 1.3 拼接关键header信息，包括content-type、根域名host、请求时间x-tc-timestamp
	//     生成签名有效期的时间为60分钟
	canonicalHeaders := fmt.Sprintf("content-type:%s\nhost:%s\nx-tc-timestamp:%s\n", ts.HeaderContent.ContentType, ts.HeaderContent.Host, ts.HeaderContent.XTCTimestamp)
	// 1.4 设置常量签名头字符串
	signedHeaders := "content-type;host;x-tc-timestamp;"
	// 1.5 对常量payload进行hash计算
	requestPayload := ""
	hashedRequestPayload := ts.sha256hex(requestPayload)
	// 1.6 按照固定格式拼接所有请求信息
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		httpRequestMethod,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		hashedRequestPayload)
	//log.Println("canonicalRequest:", canonicalRequest)

	// 2. 构造用于计算签名的字符串
	// 2.1 设置签名算法
	algorithm := "TC3-HMAC-SHA256"
	// 2.2 构造请求时间，根据请求header的X-TC-Timestamp字段(unix时间搓，精确到秒)，计算UTC标准日期
	requestTimestamp := ts.HeaderContent.XTCTimestamp
	timestamp, _ := strconv.ParseInt(requestTimestamp, 10, 64)
	t := time.Unix(timestamp, 0).UTC()
	// 必须为 2006-01-02 格式
	date := t.Format("2006-01-02")
	// 2.3 构造凭证范围，固定格式为：Date/service/tc3_request
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, ts.HeaderContent.XTCService)
	// 2.4 对第1步构造的 canonicalRequest 进行hash计算
	hashedCanonicalRequest := ts.sha256hex(canonicalRequest)
	// 2.5 按照固定格式构造用于签名的字符串
	string2sign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		requestTimestamp,
		credentialScope,
		hashedCanonicalRequest)
	//log.Println("string2sign", string2sign)

	// 3. 对第2步构造的字符串进行签名
	// 3.1 用平台分配secretKey对步骤2计算的标准UTC时间进行hash计算，生成secretDate
	secretDate := ts.hmacsha256(date, "TC3"+ts.secretKey)
	// 3.2 用3.1生成的secretDate对请求服务名进行hash计算，生成secretService
	secretService := ts.hmacsha256(ts.HeaderContent.XTCService, secretDate)
	// 3.3 用3.2生成的secretService对tc3_request常量字符串进行hash计算, 生成secretKey
	secretKey := ts.hmacsha256("tc3_request", secretService)
	// 3.4 用3.3生成的secretKey对第2构造的签名字符串进行hash计算，并生成最终的签名字符串
	signature := hex.EncodeToString([]byte(ts.hmacsha256(string2sign, secretKey)))
	//fmt.Println("signature", signature)

	// 4. 构造http请求头的authorization字段
	// 4.1 按照固定格式构造authorization字符串
	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		ts.secretId,
		credentialScope,
		signedHeaders,
		signature)
	// 4.2 给http请求头的Authorization字段赋值
	headers["Authorization"] = authorization
	//fmt.Println("authorization", authorization)

	return headers, authorization
}
