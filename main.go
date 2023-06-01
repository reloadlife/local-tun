package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	runtimeDebug "runtime/debug"
)

var (
	Configs []string

	HideLogs = false
)

var outbounds []option.Outbound

func parse() error {
	urlSub := flag.String("sub", "", "subscription url")
	flag.BoolVar(&HideLogs, "hide-logs", false, "hide logs")

	flag.Parse()
	if urlSub == nil {
		return fmt.Errorf("urlSub is nil, use -sub=url to set it")
	}

	if *urlSub == "" {
		return fmt.Errorf("urlSub is empty, use -sub=url to set it")
	}

	rq, err := http.NewRequest("GET", *urlSub, nil)
	if err != nil {
		return err
	}

	rq.Header.Set("User-Agent", "Filter/0.1.0 Prefer XRAY")
	r, err := http.DefaultClient.Do(rq)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	re, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return err
	}

	Configs = strings.Split(string(re), "\n")
	return nil
}

func run() (*box.Box, context.CancelFunc, error) {
	err := parse()
	if err != nil {
		return nil, nil, err
	}

	proxyTag := "direct"

	for _, v := range Configs {

		fmt.Println(v)
	}

	//uuid := UUID
	//
	//IPS := make(map[string]string)
	//list := strings.Split(IPs, ";")
	//for _, v := range list {
	//	vv := strings.Split(v, ":")
	//	if len(vv) != 2 {
	//		continue
	//	}
	//	IPS[vv[0]] = vv[1]
	//}
	//for tag, addr := range IPS {
	//	outbounds = append(outbounds, option.Outbound{
	//		Type: "vless",
	//		Tag:  fmt.Sprintf("proxy-%s", tag),
	//		VLESSOptions: option.VLESSOutboundOptions{
	//			ServerOptions: option.ServerOptions{
	//				Server:     addr,
	//				ServerPort: Port,
	//			},
	//			UUID:    uuid,
	//			Flow:    Flow,
	//			Network: "tcp",
	//			TLS: &option.OutboundTLSOptions{
	//				Enabled:    true,
	//				ServerName: ServerName,
	//				Insecure:   true,
	//				ALPN:       nil,
	//				UTLS: &option.OutboundUTLSOptions{
	//					Enabled:     true,
	//					Fingerprint: FP,
	//				},
	//				Reality: &option.OutboundRealityOptions{
	//					Enabled:   true,
	//					PublicKey: PKey,
	//					ShortID:   ShortId,
	//				},
	//			},
	//		},
	//	})
	//}

	outbounds = append(outbounds, option.Outbound{
		Type:          "direct",
		Tag:           "direct",
		DirectOptions: option.DirectOutboundOptions{},
	})

	outbounds = append(outbounds, option.Outbound{
		Type: "block",
		Tag:  "block",
	})

	tun := option.Listable[option.ListenPrefix]{}
	err = tun.UnmarshalJSON([]byte(`"172.19.0.1/30"`))
	if err != nil {
		return nil, nil, err
	}

	logs := &option.LogOptions{
		Disabled:     false,
		Level:        "info",
		Timestamp:    true,
		DisableColor: false,
	}

	if HideLogs {
		logs.Level = "error"
	}

	ctx, cancel := context.WithCancel(context.Background())
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log: logs,
			Inbounds: []option.Inbound{
				{
					Type: "mixed",
					Tag:  "mixed-in",
					MixedOptions: option.HTTPMixedInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen: option.NewListenAddress(netip.MustParseAddr(
								"0.0.0.0")),
							ListenPort:  9595,
							TCPFastOpen: true,
							InboundOptions: option.InboundOptions{
								SniffEnabled:             true,
								SniffOverrideDestination: true,
								SniffTimeout:             1,
								DomainStrategy:           0,
							},
						},
						SetSystemProxy: false,
					},
				},
				{
					Type: "tun",
					Tag:  "tun-in",
					TunOptions: option.TunInboundOptions{
						InterfaceName:          "filter_lol_tun0",
						Inet4Address:           tun,
						MTU:                    9000,
						AutoRoute:              true,
						StrictRoute:            true,
						EndpointIndependentNat: false,
					},
				},
			},
			Outbounds: outbounds,
			Route: &option.RouteOptions{
				Rules: []option.Rule{
					{
						DefaultOptions: option.DefaultRule{
							Inbound: []string{
								"mixed-in",
								"tun-in",
							},
							Protocol: []string{
								"tls",
								"http",
								"quic",
							},
							DomainRegex: []string{"^.ir$"},
							GeoIP:       []string{"ir", "private"},
							IPCIDR: []string{
								"0.0.0.0/8",
								"10.0.0.0/8",
								"fc00::/7",
								"fe80::/10",
							},
							ClashMode: "direct",
							Outbound:  "direct",
							Invert:    false,
						},
					},
					{
						DefaultOptions: option.DefaultRule{
							Inbound: []string{
								"mixed-in",
								"tun-in",
							},
							Protocol: []string{
								"tls",
								"http",
								"quic",
							},
							DomainRegex: []string{},
							Geosite:     []string{"category-ads-all"},
							IPCIDR:      []string{},
							ClashMode:   "block",
							Outbound:    "block",
							Invert:      false,
						},
					},
					{
						DefaultOptions: option.DefaultRule{
							Inbound: []string{
								"mixed-in",
								"tun-in",
							},
							Protocol: []string{
								"tls",
								"http",
								"quic",
							},
							ClashMode: proxyTag,
							Outbound:  proxyTag,
							Invert:    false,
						},
					},
				},
				AutoDetectInterface: true,
			},
		},
	})

	if err != nil {
		cancel()
		return nil, nil, err
	}

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(osSignals)
		close(osSignals)
	}()

	go func() {
		_, loaded := <-osSignals
		if loaded {
			cancel()
		}
	}()
	err = instance.Start()
	if err != nil {
		cancel()
		return nil, nil, err
	}

	return instance, cancel, nil
}

func main() {
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(osSignals)
	for {
		instance, cancel, err := run()
		if err != nil {
			fmt.Println(err)
			return
		}
		runtimeDebug.FreeOSMemory()
		for {
			osSignal := <-osSignals
			cancel()
			err := instance.Close()
			if err != nil {
				return
			}
			if osSignal != syscall.SIGHUP {
				return
			}
			break
		}
	}
}
