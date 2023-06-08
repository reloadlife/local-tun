package main

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box"
	"go.mamad.dev/local-vpn/app"
	"log"
	"os"
	"os/signal"
	"syscall"

	runtimeDebug "runtime/debug"
)

func run() (*box.Box, context.CancelFunc, error) {

	ctx, cancel := context.WithCancel(context.Background())

	options := app.GetOptions()

	if options == nil {
		cancel()
		return nil, nil, errors.New("options is nil")
	}

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: *options,
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
			err := instance.Close()
			if err != nil {
				log.Println("Error::", err.Error())
				return
			}
			if osSignal != syscall.SIGHUP {
				return
			}
			break
		}
	}
}
