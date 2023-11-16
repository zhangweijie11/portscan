package nmap

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// @Title: tcpSend
// @Description: 通过 TCP 方式获取数据
// @param protocol: 协议
// @param netloc: 资源标识符 uri
// @param data: 真实发送数据
// @param duration: 超时时间
// @param size: 响应体最大长度
// @return string:
// @return error:
func tcpSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	conn, err := net.DialTimeout(protocol, netloc, duration)
	if err != nil {
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	//读取数据
	var buf []byte              // big buffer
	var tmp = make([]byte, 256) // using small tmo buffer for demonstrating
	var length int
	for {
		//设置读取超时Deadline
		_ = conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		length, err = conn.Read(tmp)
		buf = append(buf, tmp[:length]...)
		if length < len(tmp) {
			break
		}
		if err != nil {
			break
		}
		if len(buf) > size {
			break
		}
	}
	if err != nil && err != io.EOF {
		return "", errors.New(err.Error() + " STEP3:READ")
	}
	if len(buf) == 0 {
		return "", errors.New("STEP3:response is empty")
	}
	return string(buf), nil
}

// @Title: tlsSend
// @Description: TLS 协议数据获取
// @param protocol: 请求协议
// @param netloc: 资源标识符
// @param data: 真实发送数据
// @param duration: 超时时间
// @param size:
// @return string:
// @return error:
func tlsSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	config := &tls.Config{
		//接受服务器提供的任何证书和其中的任何主机名的证书
		InsecureSkipVerify: true,
		//可接受的最小 TLS 版本
		MinVersion: tls.VersionTLS10,
	}
	dialer := &net.Dialer{
		Timeout:  duration,
		Deadline: time.Now().Add(duration * 2),
	}
	//发起 TLS 握手，建立 TLS 连接
	conn, err := tls.DialWithDialer(dialer, protocol, netloc, config)
	if err != nil {
		return "", errors.New(err.Error() + " STEP1:CONNECT")
	}
	defer conn.Close()
	_, err = io.WriteString(conn, data)
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	//读取数据
	var buf []byte              // big buffer
	var tmp = make([]byte, 256) // using small tmo buffer for demonstrating
	var length int
	for {
		//设置读取超时Deadline
		_ = conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		//读取数据
		length, err = conn.Read(tmp)
		buf = append(buf, tmp[:length]...)
		if length < len(tmp) {
			break
		}
		if err != nil {
			break
		}
		if len(buf) > size {
			break
		}
	}
	if err != nil && err != io.EOF {
		return "", errors.New(err.Error() + " STEP3:READ")
	}
	if len(buf) == 0 {
		return "", errors.New("STEP3:response is empty")
	}
	return string(buf), nil
}

// Send @Title: Send
// @Description: 发送请求基础入口方法，针对是不是 TLS 协议进行不同的操作
// @param protocol: 协议
// @param tls: 是否为 TLS 协议
// @param netloc: 资源标识符 uri
// @param data: 真实发送数据
// @param duration:  超时时间
// @param size: 接受响应体大小
// @return string:
// @return error:
func Send(protocol string, tls bool, netloc string, data string, duration time.Duration, size int) (string, error) {
	if tls {
		return tlsSend(protocol, netloc, data, duration, size)
	} else {
		return tcpSend(protocol, netloc, data, duration, size)
	}
}
