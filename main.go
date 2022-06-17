package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/elitah/chanpool"
	"github.com/elitah/utils/random"
)

type Buffer struct {
	Data   [4 * 1024]byte
	Length int

	address *net.UDPAddr

	offset int
}

func (this *Buffer) Reset() {
	//
	this.offset = 0
}

func (this *Buffer) FixupTailWithNewLine(n int) bool {
	//
	if 4 < n {
		//
		tailHex := (uint32(this.Data[n-4]) << 24) |
			(uint32(this.Data[n-3]) << 16) |
			(uint32(this.Data[n-2]) << 8) |
			(uint32(this.Data[n-1]) << 0)
		//
		if 0xD0A0D0A != tailHex {
			//
			if 0xD0A == tailHex&0xFFFF {
				//
				n += copy(this.Data[n:], []byte{0xD, 0xA})
			} else {
				//
				n += copy(this.Data[n:], []byte{0xD, 0xA, 0xD, 0xA})
			}
		}
		//
		//fmt.Printf("%X\n", this.Data[:n])
		//
		this.Length = n
		//
		return true
	}
	//
	return false
}

func (this *Buffer) Read(p []byte) (int, error) {
	//
	if this.Length > this.offset {
		//
		var n = copy(p, this.Data[this.offset:this.Length])
		//
		this.offset += n
		//
		return n, nil
	} else {
		//
		return 0, io.EOF
	}
}

func (this *Buffer) String() string {
	//
	return string(this.Data[:this.Length])
}

type myChanPool struct {
	//
	chanpool.ChanPool
}

func (this *myChanPool) Get() *Buffer {
	//
	if v, ok := this.ChanPool.Get().(*Buffer); ok {
		//
		return v
	}
	//
	return nil
}

func (this *myChanPool) Put(p *Buffer) {
	//
	p.Reset()
	//
	p.Length = 0
	//
	this.ChanPool.Put(p)
}

func checkInterface(iface *net.Interface) bool {
	//
	if net.FlagUp != iface.Flags&net.FlagUp {
		//
		return false
	}
	//
	if net.FlagBroadcast != iface.Flags&net.FlagBroadcast {
		//
		return false
	}
	//
	if net.FlagLoopback == iface.Flags&net.FlagLoopback {
		//
		return false
	}
	//
	if net.FlagPointToPoint == iface.Flags&net.FlagPointToPoint {
		//
		return false
	}
	//
	if net.FlagMulticast != iface.Flags&net.FlagMulticast {
		//
		return false
	}
	//
	if list, err := iface.Addrs(); nil != err {
		//
		return false
	} else if 0 == len(list) {
		//
		return false
	} else {
		//
		found := false
		//
		for _, item := range list {
			//
			if ip, _, err := net.ParseCIDR(item.String()); nil == err {
				//
				found = nil != ip.To4()
				//
				if found {
					//
					break
				}
			}
		}
		//
		if !found {
			//
			return false
		}
	}
	//
	return true
}

func multicastAtInterface(pool *myChanPool, ch chan *Buffer, name string, args ...string) error {
	//
	if iface, err := net.InterfaceByName(name); nil == err {
		//
		var designee string
		//
		for _, item := range args {
			//
			if "" != item {
				//
				designee = item
			}
		}
		//
		fmt.Println(name, "start listening...")
		//
		if conn, err := net.ListenMulticastUDP("udp4", iface, &net.UDPAddr{
			IP:   net.IPv4(239, 255, 255, 250),
			Port: 1900,
		}); nil == err {
			//
			go func(conn *net.UDPConn) {
				//
				var buf *Buffer
				//
				defer conn.Close()
				//
				for {
					//
					if nil == buf {
						//
						buf = pool.Get()
					}
					//
					if nil == buf {
						//
						return
					}
					//
					if n, address, err := conn.ReadFromUDP(buf.Data[:]); nil == err {
						//
						if "" != designee && designee != address.IP.String() {
							//
							continue
						}
						//
						if buf.FixupTailWithNewLine(n) {
							//
							buf.address = address
							//
							ch <- buf
							//
							buf = nil
						}
					}
				}
			}(conn)
			//
			return nil
		} else {
			//
			return err
		}
	} else {
		//
		return err
	}
}

func searchAtInterface(name string, timeout int) (result []*url.URL) {
	//
	if iface, err := net.InterfaceByName(name); nil == err {
		//
		if list, err := iface.Addrs(); nil == err {
			//
			for _, item := range list {
				//
				if ip, _, err := net.ParseCIDR(item.String()); nil == err {
					//
					if ip = ip.To4(); nil != ip {
						//
						if conn, err := net.ListenUDP("udp4", &net.UDPAddr{
							IP: ip,
						}); nil == err {
							//
							var b bytes.Buffer
							//
							var buffer [1024]byte
							//
							if 0 == timeout {
								//
								timeout = 3
							}
							//
							fmt.Println("start at:", conn.LocalAddr().String())
							//
							exit := make(chan struct{})
							//
							b.WriteString("M-SEARCH * HTTP/1.1\r\n")
							//
							fmt.Fprintf(&b, "MX: %d\r\n", timeout)
							//
							b.WriteString("ST: upnp:rootdevice\r\n")
							b.WriteString("MAN: \"ssdp:discover\"\r\n")
							b.WriteString("User-Agent: DLNA-Proxy-Server\r\n")
							b.WriteString("Connection: close\r\n")
							b.WriteString("Host: 239.255.255.250:1900\r\n")
							b.WriteString("\r\n")
							//
							go func() {
								//
								t := time.NewTicker(time.Second)
								//
								for {
									//
									conn.WriteToUDP(b.Bytes(), &net.UDPAddr{
										IP:   net.IPv4(239, 255, 255, 250),
										Port: 1900,
									})
									//
									conn.WriteToUDP(b.Bytes(), &net.UDPAddr{
										IP:   net.IPv4(255, 255, 255, 255),
										Port: 1900,
									})
									//
									select {
									case <-exit:
										//
										return
									case <-t.C:
									}
								}
							}()
							//
							conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
							//
							for {
								//
								if n, err := conn.Read(buffer[:]); nil == err {
									//
									tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(buffer[:n])))
									//
									if s, err := tp.ReadLine(); nil == err {
										//
										if strings.HasPrefix(s, "HTTP/") {
											//
											if h, err := tp.ReadMIMEHeader(); nil == err {
												//
												if u, err := url.Parse(h.Get("Location")); nil == err {
													//
													_url := u.String()
													//
													for _, item := range result {
														//
														if item.String() == _url {
															//
															_url = ""
														}
													}
													//
													if "" != _url {
														//
														result = append(result, u)
													}
												}
											}
										}
									}
								} else {
									//
									return
								}
							}
							//
							close(exit)
							//
							conn.Close()
						}
					}
				}
			}
		}
	}
	//
	return
}

func processDeviceSearch(pool *myChanPool, ch chan *Buffer, uuid string, httpport int, designee string) {
	//
	if list, err := net.Interfaces(); nil == err {
		//
		for _, item := range list {
			//
			if checkInterface(&item) {
				//
				if err := multicastAtInterface(pool, ch, item.Name, designee); nil != err {
					//
					fmt.Println("multicastAtInterface:", err)
				}
			} else {
				//
				//fmt.Println(item.Name, "xxxxxxxxxxxxxxxxxxxx>")
			}
		}
	}
	//
	for {
		//
		select {
		case buf, ok := <-ch:
			//
			if ok {
				//
				tp := textproto.NewReader(bufio.NewReader(buf))
				//
				if s, err := tp.ReadLine(); nil == err {
					//
					if strings.HasPrefix(s, "M-SEARCH * ") {
						//
						if h, err := tp.ReadMIMEHeader(); nil == err {
							//
							if stField := h.Get("ST"); strings.Contains(stField, "upnp:rootdevice") || true {
								//
								if manField := h.Get("MAN"); strings.Contains(manField, "ssdp:discover") {
									//
									if conn, err := net.DialUDP("udp4", nil, buf.address); nil == err {
										//
										if address, ok := conn.LocalAddr().(*net.UDPAddr); ok {
											//
											var b bytes.Buffer
											//
											b.WriteString("HTTP/1.1 200 OK\r\n")
											//
											fmt.Fprintf(
												&b,
												"ST: %s\r\nUSN: uuid:%s::upnp:rootdevice\r\nLocation: http://%s:%d/description.xml\r\n",
												stField,
												uuid,
												address.IP.String(),
												httpport,
											)
											//
											b.WriteString("OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n")
											b.WriteString("Cache-Control: max-age=300\r\n")
											b.WriteString("Server: DLNA-Proxy-Server\r\n")
											b.WriteString("Ext: \r\n")
											b.WriteString("\r\n")
											//
											conn.Write(b.Bytes())
										}
										//
										conn.Close()
									} else {
										//
										fmt.Println("net.DialUDP:", err)
									}
								} else {
									//
									//fmt.Println("no ssdp:discover")
								}
							} else {
								//
								//fmt.Println("no upnp:rootdevice")
							}
						} else {
							//
							fmt.Println("tp.ReadMIMEHeader:", err)
						}
					} else {
						//
						//fmt.Println("not M-SEARCH message")
					}
				} else {
					//
					fmt.Println("tp.ReadLine:", err)
				}
				//
				pool.Put(buf)
			} else {
				//
				return
			}
		}
	}
}

func doSearchMode(timeout int) {
	//
	var ifname string
	//
	if 2 <= flag.NArg() {
		//
		ifname = flag.Args()[1]
	}
	//
	if list, err := net.Interfaces(); nil == err {
		//
		var mutex sync.Mutex
		//
		var wg sync.WaitGroup
		//
		var urls []*url.URL
		//
		for _, item := range list {
			//
			if !checkInterface(&item) {
				//
				continue
			}
			//
			if "" == ifname || ifname == item.Name {
				//
				wg.Add(1)
				//
				go func(name string) {
					//
					_urls := searchAtInterface(name, timeout)
					//
					if 0 < len(_urls) {
						//
						mutex.Lock()
						//
						urls = append(urls, _urls...)
						//
						mutex.Unlock()
					}
					//
					wg.Done()
				}(item.Name)
			}
		}
		//
		wg.Wait()
		//
		fmt.Println("================================================")
		//
		for i, url := range urls {
			//
			fmt.Println("[", i+1, "]:", url)
		}
	}
	//
	return
}

func doSSDPMode() {
	//
	if 2 <= flag.NArg() {
		//
		if address, err := net.ResolveUDPAddr("udp4", flag.Args()[1]); nil == err {
			//
			if conn, err := net.ListenUDP("udp4", &net.UDPAddr{}); nil == err {
				//
				var buffer [1024]byte
				//
				var b bytes.Buffer
				//
				exit := make(chan struct{})
				//
				b.WriteString("M-SEARCH * HTTP/1.1\r\n")
				b.WriteString("MX: 3\r\n")
				b.WriteString("ST: upnp:rootdevice\r\n")
				b.WriteString("MAN: \"ssdp:discover\"\r\n")
				b.WriteString("User-Agent: DLNA-Proxy-Server\r\n")
				b.WriteString("Connection: close\r\n")
				b.WriteString("Host: 239.255.255.250:1900\r\n")
				b.WriteString("\r\n")
				//
				go func() {
					//
					t := time.NewTicker(time.Second)
					//
					for {
						//
						fmt.Println("send to:", address.String())
						//
						conn.WriteToUDP(b.Bytes(), address)
						//
						select {
						case <-exit:
							//
							return
						case <-t.C:
						}
					}
				}()
				//
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				//
				for {
					//
					if n, err := conn.Read(buffer[:]); nil == err {
						//
						fmt.Println(string(buffer[:n]))
					} else {
						//
						return
					}
				}
			}
		}
	}
}

func main() {
	//
	var httpport, timeout int
	//
	var target, designee, uuid, shell string
	//
	flag.IntVar(&httpport, "h", 8808, "your http server port")
	flag.IntVar(&timeout, "timeout", 3, "search timeout")
	flag.StringVar(&target, "t", "", "your target address")
	flag.StringVar(&designee, "d", "", "your designee address")
	flag.StringVar(&uuid, "u", "", "your uuid string")
	flag.StringVar(&shell, "s", "", "your shell script file path")
	//
	flag.Parse()
	//
	if 0 < flag.NArg() {
		//
		switch flag.Args()[0] {
		case "search":
			//
			if 0 > timeout {
				//
				timeout = 3
			} else if 30 < timeout {
				//
				timeout = 30
			}
			//
			doSearchMode(timeout)
			//
			return
		case "ssdp":
			//
			doSSDPMode()
			//
			return
		}
	}
	//
	if !(0 < httpport && 65536 > httpport) {
		//
		fmt.Println("invalid http server port:", httpport)
		//
		return
	}
	//
	if "" == target {
		//
		fmt.Println("empty target address!")
		//
		return
	} else {
		//
		if conn, err := net.DialTimeout("tcp4", target, 5*time.Second); nil == err {
			//
			conn.Close()
		} else {
			//
			fmt.Printf("can't connect to: %s, %v\n", target, err)
			//
			return
		}
	}
	//
	if "" == uuid {
		//
		uuid = random.NewRandomUUIDByKernel()
	}
	//
	if "" != shell {
		//
		switch {
		default:
			//
			if info, err := os.Stat(shell); nil == err {
				//
				if !info.IsDir() {
					//
					if 16 <= info.Size() {
						//
						if cwd, err := os.Readlink("/proc/self/cwd"); nil == err {
							//
							shell = filepath.Join(cwd, info.Name())
							//
							fmt.Println("shell file:", shell)
							//
							if 0 == info.Mode()&0100 {
								//
								os.Chmod(shell, info.Mode()|0100)
							}
							//
							break
						} else {
							//
							fmt.Println("os.Readlink:", err)
						}
					} else {
						//
						fmt.Println("too small")
					}
				} else {
					//
					fmt.Println("is folder")
				}
			} else {
				//
				fmt.Println("os.Stat:", err)
			}
			//
			shell = ""
		}
	}
	//
	pool := myChanPool{
		ChanPool: chanpool.NewChanPool(32, func() interface{} {
			return &Buffer{}
		}),
	}
	//
	ch := make(chan *Buffer, 32)
	//
	go processDeviceSearch(&pool, ch, uuid, httpport, designee)
	//
	fmt.Println("http.ListenAndServe:", http.ListenAndServe(fmt.Sprintf(":%d", httpport), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//
		var b bytes.Buffer
		//
		host, _, _ := net.SplitHostPort(r.Host)
		//
		if "" == host {
			//
			host = r.Host
		}
		//
		fmt.Println(r.RemoteAddr, r.Method, host, r.RequestURI)
		//
		switch r.URL.Path {
		case "/description.xml":
			//
			r.Body.Close()
			//
			fmt.Fprintf(
				w,
				`<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
   <specVersion>
      <major>1</major>
      <minor>0</minor>
   </specVersion>
   <URLBase>http://%s:%d</URLBase>
   <device>
      <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
      <friendlyName>投屏代理</friendlyName>
      <manufacturer></manufacturer>
      <manufacturerURL></manufacturerURL>
      <modelDescription></modelDescription>
      <modelName></modelName>
      <modelNumber></modelNumber>
      <modelURL></modelURL>
      <UDN>uuid:%s</UDN>
      <dlna:X_DLNADOC xmlns:dlna="urn:schemas-dlna-org:device-1-0">DMR-1.50</dlna:X_DLNADOC>
      <serviceList>
         <service>
            <serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>
            <serviceId>urn:upnp-org:serviceId:AVTransport</serviceId>
            <SCPDURL>AVTransport.scpd.xml</SCPDURL>
            <controlURL>_urn:schemas-upnp-org:service:AVTransport_control</controlURL>
            <eventSubURL>_urn:schemas-upnp-org:service:AVTransport_event</eventSubURL>
         </service>
      </serviceList>
   </device>
</root>
`,
				host,
				httpport,
				uuid,
			)
			//
			return
		}
		//
		if "POST" == r.Method || "PUT" == r.Method {
			//
			io.Copy(&b, r.Body)
			//
			if "" != shell {
				//
				if strings.HasSuffix(
					r.Header.Get("SOAPAction"),
					"#SetAVTransportURI\"",
				) {
					//
					var result struct {
						EncodingStyle string `xml:"encodingStyle,attr"`
						Soap          string `xml:"s,attr"`
						Body          struct {
							SetAVTransportURI struct {
								URN                string `xml:"u,attr"`
								InstanceID         int    `xml:"InstanceID"`
								CurrentURI         string `xml:"CurrentURI"`
								CurrentURIMetaData string `xml:"CurrentURIMetaData"`
							}
						}
					}
					//
					//fmt.Println(b.String())
					//
					if err := xml.Unmarshal(b.Bytes(), &result); nil == err {
						//
						//fmt.Printf("%+v\n", result)
						//
						if "" != result.Body.SetAVTransportURI.CurrentURI {
							//
							var newurl string
							//
							if bash_path := os.Getenv("SHELL"); "" != bash_path {
								//
								if cwd, err := os.Readlink("/proc/self/cwd"); nil == err {
									//
									if f, err := os.Open(os.DevNull); nil == err {
										//
										if r, w, err := os.Pipe(); nil == err {
											//
											exit := make(chan struct{})
											//
											if p, err := os.StartProcess(
												bash_path,
												[]string{
													"bash",
													shell,
													result.Body.SetAVTransportURI.CurrentURI,
												},
												&os.ProcAttr{
													Dir:   cwd,
													Files: []*os.File{f, w, os.Stderr},
												},
											); nil == err {
												//
												go func(exit chan struct{}, r io.Reader, url *string) {
													//
													var result struct {
														URL string `json:"url"`
													}
													//
													dec := json.NewDecoder(r)
													//
													for {
														//
														if err := dec.Decode(&result); nil == err {
															//
															*url = result.URL
														} else {
															//
															break
														}
													}
													//
													close(exit)
												}(exit, r, &newurl)
												//
												p.Wait()
											} else {
												//
												close(exit)
											}
											//
											w.Close()
											//
											r.Close()
											//
											<-exit
										}
										//
										f.Close()
									}
								}
							}
							//
							if "" != newurl {
								//
								if data, err := xml.Marshal(&struct {
									XMLName       xml.Name `xml:"s:Envelope"`
									EncodingStyle string   `xml:"s:encodingStyle,attr"`
									Soap          string   `xml:"xmlns:s,attr"`
									Body          interface{}
								}{
									EncodingStyle: result.EncodingStyle,
									Soap:          result.Soap,
									Body: struct {
										XMLName           xml.Name `xml:"s:Body"`
										SetAVTransportURI interface{}
									}{
										SetAVTransportURI: struct {
											XMLName            xml.Name `xml:"u:SetAVTransportURI"`
											URN                string   `xml:"xmlns:u,attr"`
											InstanceID         int      `xml:"InstanceID"`
											CurrentURI         string   `xml:"CurrentURI"`
											CurrentURIMetaData []byte   `xml:"CurrentURIMetaData"`
										}{
											URN:                result.Body.SetAVTransportURI.URN,
											InstanceID:         result.Body.SetAVTransportURI.InstanceID,
											CurrentURI:         newurl,
											CurrentURIMetaData: []byte(result.Body.SetAVTransportURI.CurrentURIMetaData),
										},
									},
								}); nil == err {
									//
									b.Reset()
									//
									b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
									b.WriteString("\r\n")
									//
									b.Write(data)
									//
									fmt.Println(b.String())
								} else {
									//
									fmt.Println("xml.Marshal:", err)
								}
							}
						}
					} else {
						//
						fmt.Println("xml.Unmarshal:", err)
					}
				} else if strings.HasSuffix(
					r.Header.Get("SOAPAction"),
					"#Stop\"",
				) {
					//
					if bash_path := os.Getenv("SHELL"); "" != bash_path {
						//
						if cwd, err := os.Readlink("/proc/self/cwd"); nil == err {
							//
							if p, err := os.StartProcess(
								bash_path,
								[]string{
									"bash",
									shell,
								},
								&os.ProcAttr{
									Dir:   cwd,
									Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
								},
							); nil == err {
								//
								p.Wait()
							}
						}
					}
				}
			}
		}
		//
		r.Body.Close()
		//
		for i := 0; 3 > i; i++ {
			//
			if req, err := http.NewRequest(
				r.Method,
				fmt.Sprintf(
					"http://%s%s",
					target,
					r.RequestURI,
				),
				&b,
			); nil == err {
				//
				for key, values := range r.Header {
					//
					if "Host" == key {
						//
						continue
					}
					//
					for _, item := range values {
						//
						req.Header.Add(key, item)
					}
				}
				//
				if resp, err := http.DefaultClient.Do(req); nil == err {
					//
					header := w.Header()
					//
					for key, values := range resp.Header {
						//
						for _, item := range values {
							//
							header.Add(key, item)
						}
					}
					//
					w.WriteHeader(resp.StatusCode)
					//
					io.Copy(w, resp.Body)
					//
					return
				} else {
					//
					fmt.Println("http.DefaultClient.Do:", err)
				}
			} else {
				//
				fmt.Println("http.NewRequest:", err)
			}
		}
		//
		fmt.Println("http error: not found!!!")
		//
		http.NotFound(w, r)
	})))
}
