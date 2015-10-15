// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcapdump binary implements a tcpdump-like command line tool with gopacket
// using pcap as a backend data collection mechanism.
package main

import (
	zmq "github.com/pebbe/zmq4"
	"path/filepath"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcap"
	"log"
	"os"
	"strings"
	"time"
)

var queues_num = flag.Int("q", 2, "Num of queues to publish to")
var decoder     = flag.String("decoder", "Ethernet", "Name of the decoder to use")
var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")
var processed_packets = 0
var publishers []*zmq.Socket = nil

func create_pub_socket(addr string) (*zmq.Socket) {
	socket, _ := zmq.NewSocket(zmq.PUB)
	socket.Bind(addr)	
	return socket
}

func setup_publishers(n int) ([]*zmq.Socket) {
	pub_sockets := make([]*zmq.Socket, n)

	for i := 0; i < n; i++ {
		pub_sockets[i] = create_pub_socket(fmt.Sprintf("tcp://0.0.0.0:%d", 5550+i))
	}

	return pub_sockets
}

func get_files(path string) ([]string) {
	files, _ := filepath.Glob(path)
	return files
}

func run_handle(handle gopacket.PacketDataSource) {
	var dec gopacket.Decoder
	var ok bool

	if dec, ok = gopacket.DecodersByLayerName[*decoder]; !ok {
		log.Fatalln("No decoder named", *decoder)
	}
        source := gopacket.NewPacketSource(handle, dec)
        for packet := range source.Packets() {
                processed_packets += 1
                packet_data := packet.Data()
                if processed_packets % 100000 == 0 {
                        fmt.Printf("Packets: %d\n", processed_packets)
                }
                publisher := publishers[processed_packets % *queues_num]
                publisher.SendMessage(packet_data)
        }
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	publishers = setup_publishers(*queues_num)

	if *fname != "" {
		files := get_files(*fname)

		for i := 0; i < len(files); i++ {

			fmt.Printf("pattern: %s num files: %d running: %s\n", *fname, len(files), files[i]);


			if handle, err = pcap.OpenOffline(files[i]); err != nil {
				log.Fatal("PCAP OpenOffline error:", err)
			}	

			run_handle(handle)
		}



	} else {
		// This is a little complicated because we want to allow all possible options
		// for creating the packet capture handle... instead of all this you can
		// just call pcap.OpenLive if you want a simple handle.
		inactive, err := pcap.NewInactiveHandle(*iface)
		if err != nil {
			log.Fatal("could not create: %v", err)
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(*snaplen); err != nil {
			log.Fatal("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(*promisc); err != nil {
			log.Fatal("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			log.Fatal("could not set timeout: %v", err)
		}
		if *tstype != "" {
			if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			} else if err := inactive.SetTimestampSource(t); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			}
		}
		if handle, err = inactive.Activate(); err != nil {
			log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
		if len(flag.Args()) > 0 {
			bpffilter := strings.Join(flag.Args(), " ")
			fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
			if err = handle.SetBPFFilter(bpffilter); err != nil {
				log.Fatal("BPF filter error:", err)
			}
		}

		run_handle(handle)
	}

}
