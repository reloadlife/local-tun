package app

import (
	"github.com/sagernet/sing-box/option"
)

func GetDNS() *option.DNSOptions {
	servers := []option.DNSServerOptions{
		{
			Tag:     "cf",
			Address: "tls://1.1.1.1",
		},
		{
			Tag:     "block",
			Address: "rcode://success",
		},
	}

	dnsOption := option.DNSOptions{
		Servers: servers,
		Rules: []option.DNSRule{
			{
				DefaultOptions: option.DefaultDNSRule{
					Geosite: []string{
						"category-ads-all",
					},
					Server:       "block",
					DisableCache: true,
				},
			},
		},
		Final: "cf",
		DNSClientOptions: option.DNSClientOptions{
			Strategy:      0,
			DisableCache:  true,
			DisableExpire: true,
		},
	}

	return &dnsOption
}
