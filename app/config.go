package app

import (
	"fmt"
	"github.com/sagernet/sing-box/option"
	"net/netip"
)

var (
	UUID       string = ""
	Port       uint16 = 0
	PKey       string = ""
	ShortId    string = ""
	FP         string = ""
	ServerName string = ""
	Flow       string = ""
)

var rule []option.Rule

func GetOptions() *option.Options {
	uuid := UUID

	tun := option.Listable[option.ListenPrefix]{}
	err := tun.UnmarshalJSON([]byte(`"172.19.0.1/30"`))
	if err != nil {
		return nil
	}

	var outbounds []option.Outbound
	IPS := map[string]string{
		// tag + IP
	}
	for tag, addr := range IPS {
		outbounds = append(outbounds, option.Outbound{
			Type: "vless",
			Tag:  fmt.Sprintf("proxy-%s-vless", tag),
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
		Type: "dns",
		Tag:  "dns-out",
	})

	outbounds = append(outbounds, option.Outbound{
		Type: "direct",
		Tag:  "direct",
	})

	rulesAppend()
	options := option.Options{
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
						Listen:      option.NewListenAddress(netip.MustParseAddr("0.0.0.0")),
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
					InterfaceName:          "filter_lol_tun",
					MTU:                    9000,
					Inet4Address:           tun,
					AutoRoute:              true,
					StrictRoute:            true,
					EndpointIndependentNat: false,
					Stack:                  GetStack(),
					InboundOptions: option.InboundOptions{
						SniffEnabled:             true,
						SniffOverrideDestination: true,
						SniffTimeout:             1,
						DomainStrategy:           0,
					},
				},
			},
		},
		Outbounds: append(outbounds, option.Outbound{
			Type: "block",
			Tag:  "block",
		}),
		DNS: GetDNS(),
		Route: &option.RouteOptions{
			Rules:               rule,
			AutoDetectInterface: true,
		},
	}

	return &options
}
