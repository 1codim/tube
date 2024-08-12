package main

import (
	"io"
	"os"
	"os/signal"
	"net"
	"net/http"
	"time"
	"bufio"
	"errors"
	"regexp"
	"context"
	"strconv"
	"strings"
	"syscall"
	"github.com/likexian/doh"
	"github.com/likexian/doh/dns"
)

type Packet struct {
	raw     []byte
	method  string
	domain  string
	port    string
	path    string
	version string
}

func Read(conn *net.TCPConn) ([]byte, error) {
	ret := make([]byte, 0)
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			switch err.(type) {
			case *net.OpError:
				return nil, errors.New("timed out")
			default:
				return nil, err
			}
		}
		ret = append(ret, buf[:n]...)
		if n < 1024 {
			break
		}
	}
	if len(ret) == 0 {
		return nil, io.EOF
	}
	return ret, nil
}

func Write(from *net.TCPConn, to *net.TCPConn) {
	for {
		buf, err := Read(from)
		if err != nil {
			if err == io.EOF {
				return
			}
			return
		}
		if _, err := to.Write(buf); err != nil {
			return
		}
	}
}

func proxyHttp(lConn *net.TCPConn, pkt *Packet, ip string) {
	var port int = 80
	var err error
	s := string(pkt.raw)
	lines := strings.Split(s, "\r\n")
	lines[0] = pkt.method + " " + pkt.path + " " + pkt.version
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "Proxy-Connection") {
			lines[i] = ""
		}
	}
	result := ""
	for i := 0; i < len(lines); i++ {
		if lines[i] == "" {
			continue
		}
		result += lines[i] + "\r\n"
	}
	result += "\r\n"
	pkt.raw = []byte(result)
	if pkt.port != "" {
		port, err = strconv.Atoi(pkt.port)
		if err != nil {
		}
	}
	rConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP(ip), Port: port})
	if err != nil {
		lConn.Close()
		return
	}
	defer func() {
		lConn.Close()
		rConn.Close()
	}()
	go Write(rConn, lConn)
	_, err = rConn.Write(pkt.raw)
	if err != nil {
		return
	}
	Write(lConn, rConn)
}

func proxyHttps(lConn *net.TCPConn, initPkt *Packet, ip string, allowedUrl *regexp.Regexp) {
	var port int = 443
	var err error
	if initPkt.port != "" {
		port, err = strconv.Atoi(initPkt.port)
		if err != nil {

		}
	}
	rConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.ParseIP(ip), Port: port})
	if err != nil {
		lConn.Close()
		return
	}
	defer func() {
		lConn.Close()
		rConn.Close()
	}()
	_, err = lConn.Write([]byte(initPkt.version + " 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}
	clientHello, err := Read(lConn)
	if err != nil {
		return
	}
	chPkt := Packet{
		raw: clientHello,
	}
	go Write(rConn, lConn)
	if !(allowedUrl != nil && allowedUrl.Match([]byte(initPkt.domain))) {
		if _, err := rConn.Write(chPkt.raw); err != nil {
			return
		}
	} else {
		chunks := [][]byte{chPkt.raw}
    if allowedUrl != nil && allowedUrl.Match(chPkt.raw) {
	    var raw []byte = chPkt.raw
	    if len(raw) < 1 {
	    	chunks = [][]byte{raw}
	    } else {
	    	chunks = [][]byte{raw[:1], raw[1:]}
	    }
	  }
	  for i := 0; i < len(chunks); i++ {
	  	_, err := rConn.Write(chunks[i])
	  	if err != nil {
	  		return
	  	}
	  }
	}
	Write(lConn, rConn)
}

func Run(allowedUrl *regexp.Regexp) {
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080})
	if err != nil {
		os.Exit(1)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			continue
		}
		go func() {
			b, err := Read(conn.(*net.TCPConn))
			if err != nil {
				return
			}
			pkt := &Packet{raw: b}
	    reader := bufio.NewReader(strings.NewReader(string(pkt.raw)))
	    request, err := http.ReadRequest(reader)
	    if err == nil {
	      pkt.domain, pkt.port, err = net.SplitHostPort(request.Host)
	      if err != nil {
	      	pkt.domain = request.Host
	      	pkt.port = ""
	      }
	      pkt.method = request.Method
	      pkt.version = request.Proto
	      pkt.path = request.URL.Path
	      if request.URL.RawQuery != "" {
	      	pkt.path += "?" + request.URL.RawQuery
	      }
	      if request.URL.RawFragment != "" {
	      	pkt.path += "#" + request.URL.RawFragment
	      }
	      if pkt.path == "" {
	      	pkt.path = "/"
	      }
	      request.Body.Close()
	    } else {
	    	conn.Close()
				return
	    }
      ip := ""
      isIp, _ := regexp.MatchString("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", pkt.domain)
	    if isIp {
        ip = pkt.domain
	    } else {
          ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	        defer cancel()
	        c := doh.Use(doh.CloudflareProvider, doh.GoogleProvider)
	        rsp, err := c.Query(ctx, dns.Domain(pkt.domain), "A")
          if err == nil {
	    	    answer := rsp.Answer
	          for _, a := range answer {
	          	if a.Type != 1 {
	          		continue
	          	}
	          	ip = a.Data
	          }
	        }
          c.Close()
	    }
	    if ip == "" {
				conn.Write([]byte(pkt.version + " 502 Bad Gateway\r\n\r\n"))
				conn.Close()
				return
			}
			isLooped := false
			parsedIP := net.ParseIP(ip)
			if parsedIP.To4() != nil {
			  addr, err := net.InterfaceAddrs()
	      if err == nil {
	      	for _, addr := range addr {
	        	if ipnet, ok := addr.(*net.IPNet); ok {
	        		if ipnet.IP.To4() != nil && ipnet.IP.To4().Equal(parsedIP) {
	        			isLooped = true
	        		}
	        	}
	        }
	      }
	    }
			if pkt.port == strconv.Itoa(1080) && isLooped {
				conn.Close()
				return
			}
			if pkt.method == "CONNECT" {
				proxyHttps(conn.(*net.TCPConn), pkt, ip, allowedUrl)
			} else {
				proxyHttp(conn.(*net.TCPConn), pkt, ip)
			}
		}()
	}
}

func main() {
  allowedUrl, _ := regexp.Compile("googlevideo.com|i.ytimg.com|youtube.com")
	go Run(allowedUrl)
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs,	syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	go func() {
		_ = <-sigs
		done <- true
	}()
	<-done
}
