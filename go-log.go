package main

import (
	"fmt"
	"github.com/Kong/go-pdk"
	"os"
)

type Config struct {
	Path   string
	Reopen bool
}

var fileDescriptors map[string]*os.File
var channels map[string]chan []byte

func New() interface{} {
	return &Config{}
}

func (conf Config) Access(kong *pdk.PDK) {
	host, err := kong.Request.GetHeader("host")
	if err != nil {
		kong.Log.Err(err.Error())
	}
	kong.Response.SetHeader("x-hello-go", fmt.Sprintf("Go says hello to %s (%s)", host, conf.Path))
}

func (conf Config) Log(kong *pdk.PDK) {
	if channels == nil {
		channels = make(map[string]chan []byte)
	}

	ch, ok := channels[conf.Path]
	if !ok {
		channels[conf.Path] = make(chan []byte)
		ch = channels[conf.Path]

		go func() {
			for {
				b := <-ch

				if fileDescriptors == nil {
					fileDescriptors = make(map[string]*os.File)
				}

				fd, ok := fileDescriptors[conf.Path]
				if ok {
					if conf.Reopen {
						fd.Close()
						delete(fileDescriptors, conf.Path)
						ok = false
					}
				}

				if !ok {
					var err error
					fd, err = os.OpenFile(conf.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
					if err != nil {
						kong.Log.Err("failed to open the file: ", err.Error())
						return
					}
					fileDescriptors[conf.Path] = fd
				}

				fd.Write(b)
				fd.Write([]byte("\n"))
			}
		}()

	}

	log, err := kong.Log.Serialize()
	if err != nil {
		kong.Log.Err(err.Error())
	}

	ch <- []byte(log)
}
