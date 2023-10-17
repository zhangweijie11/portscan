package result

import (
	"github.com/stretchr/testify/assert"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/portlist"
	"gitlab.example.com/zhangweijie/portscan/services/pportscan/protocol"
	"testing"
)

func TestAddPort(t *testing.T) {
	targetIP := "127.0.0.1"
	targetPort := &portlist.Port{Port: 8080, Protocol: protocol.TCP}
	targetPorts := map[string]*portlist.Port{targetPort.String(): targetPort}

	res := NewPortScanResult()
	res.AddPort(targetIP, targetPort)

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, expectedIPS, res.ips)

	expectedIPSPorts := map[string]map[string]*portlist.Port{targetIP: targetPorts}
	assert.Equal(t, res.ipPorts, expectedIPSPorts)
}

func TestSetPorts(t *testing.T) {
	targetIP := "127.0.0.1"
	port80 := &portlist.Port{Port: 80, Protocol: protocol.TCP}
	port443 := &portlist.Port{Port: 443, Protocol: protocol.TCP}
	targetPorts := map[string]*portlist.Port{
		port80.String():  port80,
		port443.String(): port443,
	}

	res := NewPortScanResult()
	res.SetPorts(targetIP, []*portlist.Port{port80, port443})

	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.ips, expectedIPS)

	expectedIPSPorts := map[string]map[string]*portlist.Port{targetIP: targetPorts}
	assert.Equal(t, res.ipPorts, expectedIPSPorts)
}

func TestIPHasPort(t *testing.T) {
	targetIP := "127.0.0.1"
	expectedPort := &portlist.Port{Port: 8080, Protocol: protocol.TCP}
	unexpectedPort := &portlist.Port{Port: 8081, Protocol: protocol.TCP}

	res := NewPortScanResult()
	res.AddPort(targetIP, expectedPort)
	assert.True(t, res.IPHasPort(targetIP, expectedPort))
	assert.False(t, res.IPHasPort(targetIP, unexpectedPort))
}

func TestAddIP(t *testing.T) {
	targetIP := "127.0.0.1"

	res := NewPortScanResult()
	res.AddIp(targetIP)
	expectedIPS := map[string]struct{}{targetIP: {}}
	assert.Equal(t, res.ips, expectedIPS)
}

func TestHasIP(t *testing.T) {
	targetIP := "127.0.0.1"

	res := NewPortScanResult()
	res.AddIp(targetIP)
	assert.True(t, res.HasIP(targetIP))
	assert.False(t, res.HasIP("1.2.3.4"))
}
