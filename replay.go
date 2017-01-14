package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"

	"github.com/GregoryIan/mysql-replay/mysql"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/ngaut/log"
	"time"
)

var (
	username       string
	password       string
	host           string
	port           int
	dbname         string
	sourcePcapFile string

	workers        map[string]chan []byte
	reassemble_map map[string][]byte
	dsn            string
	done           chan int
)

const (
	DONE int = 1
)

func init() {
	flag.StringVar(&host, "host", "127.0.0.1", "host of target database")
	flag.IntVar(&port, "port", 4000, "port of target database")
	flag.StringVar(&username, "username", "root", "username of target database")
	flag.StringVar(&password, "password", "", "password of target database")
	flag.StringVar(&dbname, "dbname", "", "db name of target database")
	flag.StringVar(&sourcePcapFile, "pcap-file", "", "path of source pcap file")
}

func worker_for_some_ip(key string, ch chan []byte, done chan int) {
	var seq_id byte = 0
	var stmt_id uint32 = 0
	var packet []byte
	var cmd byte = 0

	mysqlConn, err := mysql.Open(dsn)
	if err != nil {
		log.Errorf("switch database err %v", err)
	}

	log.Infof("a new connection for %s", key)

	for {
		select {
		case packet = <-ch:
			if len(packet) == 0 {
				log.Infof("workder %s done", key)
				done <- DONE
				return
			}

			packet = mysql_packet_set_seq_id(packet, seq_id)
			cmd = mysql_packet_get_cmd(packet)

			if cmd == mysql.COM_STMT_EXECUTE || cmd == mysql.COM_STMT_CLOSE {
				if stmt_id == 0 {
					log.Errorf("stmt_id is not initialized! stmt_id=%d, skip!", stmt_id)
					continue
				}
				log.Warnf("modify stmt_id = %d", stmt_id)
				packet = mysql_packet_set_stmt_id(packet, stmt_id)
			}
			n, err := mysqlConn.NetConn.Write(packet)
			if err == io.EOF {
				log.Errorf("write packet error %v", err)
				mysqlConn, _ = mysql.Open(dsn)
				packet = mysql_packet_set_seq_id(packet, seq_id)
				n, err = mysqlConn.NetConn.Write(packet)
			} else if err != nil {
				log.Errorf("write packet error %v", err)
			} else {

			}
			log.Infof("fake send %v: %v", key, n)
			if mysql_packet_get_cmd(packet) == mysql.COM_STMT_CLOSE {
				stmt_id = 0
			}
		}
		// if mysql_packet_get_cmd(packet) != mysql.COM_STMT_PREPARE {
		// 	continue
		// }

		mysqlConn.NetConn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 65535)
		n, err := mysqlConn.NetConn.Read(buf)
		if err == io.EOF {
			log.Warnf("packet => #v", packet)
			log.Error("EOF while reading")
		} else if err != nil {
			log.Warnf("read pack error %v", err)
		} else {
			if cmd == mysql.COM_STMT_PREPARE {
				buf = buf[:n]
				if int(buf[4]) == 0 {
					stmt_id = binary.LittleEndian.Uint32(buf[5:9])
					log.Warnf("prepare reply, set stmt_id=%d", stmt_id)
				} else {
					log.Errorf("prepare stmt error. packet => %s", string(buf[13:]))
				}
			}
		}
	}
}

func main() {
	flag.Parse()

	dsn = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8", username, password, host, port, dbname)

	var handle *pcap.Handle
	var err error

	workers = make(map[string]chan []byte)
	reassemble_map = make(map[string][]byte)
	done = make(chan int, 1024)

	if err != nil {
		panic(err)
	}

	if handle, err = pcap.OpenOffline(sourcePcapFile); err != nil {
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		handlePacket(packet)
	}

	log.Info("send packets to goroutines over")

	// wait goroutines to finish
	for _, worker_ch := range workers {
		worker_ch <- []byte{} // means done
	}

	worker_num := len(workers)
	log.Infof("worker number: %d", worker_num)
	for {
		select {
		case <-done:
			worker_num -= 1
		}
		log.Infof("worker number: %d", worker_num)
		if worker_num == 0 {
			break
		}
	}

	log.Info("end play!")
}

func mysql_packet_get_cmd(raw_packet []byte) byte {
	return raw_packet[4]
}

func mysql_packet_set_seq_id(raw_packet []byte, new_id byte) []byte {
	raw_packet[3] = new_id
	return raw_packet
}

func mysql_packet_set_stmt_id(raw_packet []byte, stmt_id uint32) []byte {
	if mysql_packet_get_cmd(raw_packet) == mysql.COM_STMT_EXECUTE || mysql_packet_get_cmd(raw_packet) == mysql.COM_STMT_CLOSE {
		binary.LittleEndian.PutUint32(raw_packet[5:9], stmt_id)
	}
	return raw_packet
}

func mysql_packet_get_payload_length(raw_packet []byte) int {
	return int(raw_packet[0]) + int(raw_packet[1])<<8 + int(raw_packet[2])<<16
}

func handlePacket(packet gopacket.Packet) {
	// log.Info(packet)
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	if len(tcp.Payload) == 0 || tcp.DstPort != 4000 {
		return
	}
	// log.Infof("# %v:%d => %v:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	key := fmt.Sprintf("%v:%d->%v:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)

	data := tcp.Payload
	if old_data, ok := reassemble_map[key]; ok {
		data = append(old_data, data...)
	}

	payload_length := mysql_packet_get_payload_length(data)
	cmd := mysql_packet_get_cmd(data)

	payload := data[4:]

	// log.Debugf("got mysql packet cmd=%d len=%d pkt_len=%d", cmd, payload_length, len(payload))
	if payload_length > len(payload) {
		reassemble_map[key] = data
		log.Info("skip and wait for reassemble")
		return
	} else if payload_length < len(payload) {
		log.Errorf("should have len %v, have %v", payload_length, len(payload))
		log.Errorf("%v\n", data)
		panic("are you sb?")
	} else {
		delete(reassemble_map, key)
	}

	switch cmd {
	case mysql.COM_SLEEP, mysql.COM_QUIT, mysql.COM_PING, mysql.COM_FIELD_LIST, 133, 141:

	default:
		if ch, ok := workers[key]; ok {
			ch <- data
		} else {
			new_ch := make(chan []byte, 102400)
			go worker_for_some_ip(key, new_ch, done)
			workers[key] = new_ch
			new_ch <- data
		}
	}
}
