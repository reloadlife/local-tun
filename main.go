package main

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	runtimeDebug "runtime/debug"
)

var (
	UUID       string
	IPs        string
	Port       uint16
	PKey       string
	ShortId    string
	FP         string
	ServerName string
	Flow       string
)

func run() (*box.Box, context.CancelFunc, error) {
	uuid := UUID

	tun := option.Listable[option.ListenPrefix]{}
	err := tun.UnmarshalJSON([]byte(`"172.19.0.1/30"`))
	if err != nil {
		return nil, nil, err
	}

	var outbounds []option.Outbound
	IPS := make(map[string]string)
	list := strings.Split(IPs, ";")
	for _, v := range list {
		vv := strings.Split(v, ":")
		if len(vv) != 2 {
			continue
		}
		IPS[vv[0]] = vv[1]
	}
	for tag, addr := range IPS {
		outbounds = append(outbounds, option.Outbound{
			Type: "vless",
			Tag:  fmt.Sprintf("proxy-%s", tag),
			VLESSOptions: option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     addr,
					ServerPort: Port,
				},
				UUID:    uuid,
				Flow:    Flow,
				Network: "tcp",
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: ServerName,
					Insecure:   true,
					ALPN:       nil,
					UTLS: &option.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: FP,
					},
					Reality: &option.OutboundRealityOptions{
						Enabled:   true,
						PublicKey: PKey,
						ShortID:   ShortId,
					},
				},
			},
		})
	}

	outbounds = append(outbounds, option.Outbound{
		Type:          "direct",
		Tag:           "direct",
		DirectOptions: option.DirectOutboundOptions{},
	})

	outbounds = append(outbounds, option.Outbound{
		Type: "block",
		Tag:  "block",
	})

	ctx, cancel := context.WithCancel(context.Background())
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log: &option.LogOptions{
				Disabled:     false,
				Level:        "info",
				Timestamp:    true,
				DisableColor: false,
			},
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
			panic(err)
		}
		runtimeDebug.FreeOSMemory()
		for {
			osSignal := <-osSignals
			cancel()
			instance.Close()
			if osSignal != syscall.SIGHUP {
				return
			}
			break
		}
	}
}
