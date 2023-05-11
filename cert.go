package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
)

const (
	rootCrt = "certificate/root.crt"
	rootKey = "certificate/root.key"
)

func getCertAndKey() ([]byte, []byte, error) {
	//检查证书文件是否存在
	_, err := os.Stat(rootCrt)
	if err != nil {
		//创建证书
		if err := CreateCert(); err != nil {
			return nil, nil, err
		}
	}

	certBytes, err := ioutil.ReadFile(rootCrt)
	if err != nil {
		return nil, nil, err
	}
	pemBytes, err := ioutil.ReadFile(rootKey)
	if err != nil {
		return nil, nil, err
	}
	return certBytes, pemBytes, nil
}

func CreateCert() error {
	//生成私钥
	_, err := Command(priKeyCmd)
	if err != nil {
		fmt.Printf("生成私钥err:%v\n", err)
		return err
	}
	//生成csr配置
	_, err = Command(csrConf)
	if err != nil {
		fmt.Printf("生成csr配置err:%v\n", err)
		return err
	}
	//生成证书签名请求 (CSR)
	_, err = Command(csrCmd)
	if err != nil {
		fmt.Printf("生成签名请求CSR err:%v\n", err)
		return err
	}
	//生成证书
	_, err = Command(certCmd)
	if err != nil {
		fmt.Printf("生成证书err:%v\n", err)
		return err
	}

	return nil
}

func Command(arg ...string) (string, error) {
	name := "/bin/bash"
	c := "-c"
	args := append([]string{c}, arg...)
	cmd := exec.Command(name, args...)

	//创建获取命令输出管道
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("Error:can not obtain stdout pipe for command:%s\n", err.Error())
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	//执行命令
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("Error:The command is err:%s, cmd:%+v", err.Error(), arg)
	}

	//读取所有输出
	outBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		return "", fmt.Errorf("ReadAll Stdout:%s", err.Error())
	}

	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("wait:%s, cmd:%+v, err:%+v", err.Error(), arg, stderr.String())
	}

	result := string(outBytes)
	return result, nil
}

var (
	//生成根证书私钥
	priKeyCmd = "openssl genrsa -out certificate/root.key 2048"
	//创建证书签名请求配置文件

	//csrConf = "cat > certificate/root_csr.conf <<EOF\n[ req ]\ndefault_bits = 2048\nprompt = no\ndefault_md = sha256\ndistinguished_name = dn\nreq_extensions = v3_req\n\n[ dn ]\nC = CN\nST = Beijing\nL = Beijing\nO = zdlz\nOU = zdlz\nCN = root\n\n[v3_req]\nbasicConstraints=critical,CA:TRUE\nsubjectAltName = @alt_names\n\n[ alt_names ]\nIP.1 = 127.0.0.1\n\nEOF"
	csrConf = `cat > certificate/root_csr.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[ dn ]
C = CN
ST = Beijing
L = Beijing
O = zdlz
OU = zdlz
CN = root

[v3_req]
basicConstraints=critical,CA:TRUE
subjectAltName = @alt_names

[ alt_names ]
IP.1 = 127.0.0.1

EOF`
	//使用根私钥生成证书签名请求 (CSR)
	csrCmd = "openssl req -new -key certificate/root.key -out certificate/root.csr -config certificate/root_csr.conf"
	//自签名生成根证书，此处是自签root证书
	certCmd = "openssl x509 -req -in certificate/root.csr -out certificate/root.crt -signkey certificate/root.key -CAcreateserial -days 3650"
)

/*
国密生成私钥：
gmssl ecparam -genkey -name sm2p256v1 -out ca.key

国密gmssl通过私钥导出公钥
gmssl sm2 -in ca.key -pubout > ca.pub

生成签名文件
gmssl req -new -key ca.key -out ca.csr -config ca.conf

生成证书
gmssl x509 -req -in ca.csr -out ca.crt -signkey ca.key -days 3650
*/
