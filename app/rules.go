package app

import "github.com/sagernet/sing-box/option"

func rulesAppend() {
	rule = append(rule, option.Rule{
		DefaultOptions: option.DefaultRule{
			Protocol:  []string{"dns"},
			Port:      []uint16{53},
			ClashMode: "dns-out",
			Outbound:  "dns-out",
			Invert:    false,
		},
	})

	rule = append(rule, option.Rule{
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
	})

	rule = append(rule, option.Rule{
		DefaultOptions: option.DefaultRule{
			Inbound: []string{
				"mixed-in",
				"tun-in",
			},
			Protocol: []string{
				"tls",
				"http",
			},
			Geosite:   []string{"category-ads-all"},
			ClashMode: "block",
			Outbound:  "block",
			Invert:    false,
		},
	})
}
