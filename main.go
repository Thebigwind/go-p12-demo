package main

import (
	"encoding/base64"
	"fmt"
)

var certPwd = "1qaz2wsx"

func main() {
	//读取证书
	cert, key, err := getCertAndKey()
	if err != nil {
		fmt.Printf("err:%v", err.Error())
		return
	}

	//转成P12文件
	p12Str, err := certToP12(cert, key, certPwd)
	if err != nil {
		fmt.Printf("err:%v", err.Error())
		return
	}
	fmt.Printf("p12str:%v\n", p12Str)

	//解析P12文件
	//先转换P12文件格式
	p12Bytres, err := base64.StdEncoding.DecodeString(p12Str)
	if err != nil {
		fmt.Printf("DecodeString err:%v", err.Error())
		return
	}
	//再decode
	certbase, certsn, certafter, err := getMDMCertCont(p12Bytres, certPwd)
	if err != nil {
		fmt.Printf("err:%v", err.Error())
		return
	}
	fmt.Printf("certbase:%s\n,certsn:%s\n,certafter:%v\n", certbase, certsn, certafter)
}
