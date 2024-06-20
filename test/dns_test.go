package main

import (
	"net"
	"testing"
	"time"

	"github.com/hailsteam/requests"
)

func TestDns(t *testing.T) {
	resp, err := requests.Get(nil, "https://httpbin.org/anything", requests.RequestOption{
		/*Dns: &net.UDPAddr{ //set dns server
			IP:   net.ParseIP("223.5.5.5"),
			Port: 53,
		},*/
		ServerAddr: &net.IPAddr{ //set domain   server ip
			IP: net.ParseIP("18.211.234.122"),
		},
		Timeout:             time.Second * 88,
		TlsHandshakeTimeout: time.Second * 5,
		DialTimeout:         time.Second * 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != 200 {
		t.Fatal("http status code is not 200")
	}

	println(resp.Text())
}
