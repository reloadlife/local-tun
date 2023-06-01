package internal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/option"
	"net/url"
	"strings"
)

func ParseConfig(conf string) (*option.Outbound, error) {
	parsed, err := url.Parse(conf)
	if err != nil {
		return nil, err
	}

	if parsed.Scheme == "" {
		return nil, errors.New("scheme is empty")
	}

	scheme := parsed.Scheme
	if scheme != "vmess" && scheme != "vless" && scheme != "trojan" {
		return nil, errors.New("scheme must be vmess, vless or trojan")
	}

	if parsed.Fragment == "" {
		parsed.Fragment = parsed.Hostname()
	}

	opts := &option.Outbound{
		Tag:  fmt.Sprintf("proxy-%s", parsed.Fragment),
		Type: parsed.Scheme,
	}

	switch scheme {
	case "vmess":
		conf = strings.ReplaceAll(conf, "vmess://", "")
		de, err := base64.StdEncoding.DecodeString(conf)
		if err != nil {
			return nil, err
		}
		var res map[string]interface{}
		err = json.Unmarshal(de, &res)
		if err != nil {
			return nil, err
		}

		opts.VMessOptions = option.VMessOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     res["add"].(string),
				ServerPort: res["port"].(uint16),
			},
			UUID:                res["id"].(string),
			Security:            res["scy"].(string),
			AlterId:             res["aid"].(int),
			GlobalPadding:       false,
			AuthenticatedLength: false,
			Network:             "tcp",
			TLS: &option.OutboundTLSOptions{
				Enabled:         false,
				DisableSNI:      false,
				ServerName:      "",
				Insecure:        false,
				ALPN:            nil,
				MinVersion:      "",
				MaxVersion:      "",
				CipherSuites:    nil,
				Certificate:     "",
				CertificatePath: "",
				ECH:             nil,
				UTLS:            nil,
				Reality:         nil,
			},
			Transport: &option.V2RayTransportOptions{
				Type:             "http",
				HTTPOptions:      option.V2RayHTTPOptions{},
				WebsocketOptions: option.V2RayWebsocketOptions{},
				QUICOptions:      option.V2RayQUICOptions{},
				GRPCOptions:      option.V2RayGRPCOptions{},
			},
		}

	case "vless":
		opts.VLESSOptions = option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "",
				ServerPort: 0,
			},
		}

	case "trojan":
		opts.TrojanOptions = option.TrojanOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "",
				ServerPort: 0,
			},
		}
	}

	return opts, nil
}
