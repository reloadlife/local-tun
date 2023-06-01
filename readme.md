# SingBox

## how to build

```bash
vlessUUID=""
IPList=""
Port=""
RealityPublicKey=""
ShortId=""
fingerPrint=""
serverName=""
Flow=""
go build -o vpn -tags with_utls -ldflags "-X main.UUID=$vlessUUID -X main.IPs=$IPList -X main.Port=$Port -X main.PKey=$RealityPublicKey -X main.ShortId=$ShortId -X main.FP=$fingerPrint -X main.ServerName=$serverName -X main.Flow=$Flow"  main.go
```

## run

```bash
sudo ./vpn 
```