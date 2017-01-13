package main

import (
	//	"bufio"
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
	//	"github.com/google/gopacket/pcapgo"
	//	"github.com/google/gopacket/tcpassembly"
	//	"github.com/google/gopacket/tcpassembly/tcpreader"
)

var (
	username       string
	password       string
	host           string
	sourcePcapFile string
	//sourcePcapFile string = "/data/xindong/tcpdumps/l"
	workers   map[string]chan []byte
	reorg_map map[string][]byte
)

func init() {
	flag.StringVar(&host, "host", "127.0.0.1:4000", "host of target database")
	flag.StringVar(&username, "user", "root", "username of target database")
	flag.StringVar(&password, "password", "", "password of target database")
	flag.StringVar(&sourcePcapFile, "pcap-file", "", "path of source pcap file")
}

const (
	COM_SLEEP byte = iota
	COM_QUIT
	COM_INIT_DB
	COM_QUERY
	COM_FIELD_LIST
	COM_CREATE_DB
	COM_DROP_DB
	COM_REFRESH
	COM_SHUTDOWN
	COM_STATISTICS
	COM_PROCESS_INFO
	COM_CONNECT
	COM_PROCESS_KILL
	COM_DEBUG
	COM_PING
	COM_TIME
	COM_DELAYED_INSERT
	COM_CHANGE_USER
	COM_BINLOG_DUMP
	COM_TABLE_DUMP
	COM_CONNECT_OUT
	COM_REGISTER_SLAVE
	COM_STMT_PREPARE
	COM_STMT_EXECUTE        // 23
	COM_STMT_SEND_LONG_DATA // 24
	COM_STMT_CLOSE
	COM_STMT_RESET
	COM_SET_OPTION
	COM_STMT_FETCH
	COM_DAEMON
	COM_BINLOG_DUMP_GTID
	COM_RESET_CONNECTION
)

func worker_for_some_ip(key string, ch chan []byte) {
	var seq_id byte = 0
	var stmt_id uint32 = 0
	var packet []byte

	mysqlConn, err := mysql.Open("tcp", username, password, host)
	mysqlConn.Query("use ro_global_r1;", nil)
	if err != nil {
		panic(err)
	}

	log.Infof("a new connection")
	for {
		// conn.SetReadDeadline(time.Now().Add(time.Second))
		/*		buf := make([]byte, 65535)
				n, err := conn.Read(buf)
				if err == io.EOF {
					log.Warnf("EOF while reading")
				} else if err != nil {
					log.Warnf("read pack error %v", err)
				} else {
					buf = buf[:n]
					log.Warnf("reply packet %v", buf)
				}*/

		select {
		case packet = <-ch:
			packet = mysql_packet_set_seq_id(packet, seq_id)

			if mysql_packet_get_cmd(packet) == COM_STMT_EXECUTE ||
				mysql_packet_get_cmd(packet) == COM_STMT_CLOSE {
				seq_id = 0
				if stmt_id == 0 {
					log.Errorf("stmt_id is not initialized! stmt_id=%d, skip!", stmt_id)
					continue
				}
				log.Warnf("modify stmt_id = %d", stmt_id)
				packet = mysql_packet_set_stmt_id(packet, stmt_id)
			}
			n, err := mysqlConn.NetConn.Write(packet)
			if err != nil {
				log.Errorf("write packet error %v", err)
				mysqlConn, _ = mysql.Open("tcp", username, password, host)
				mysqlConn.Query("use ro_global_r1;", nil)
				seq_id = 0
				packet = mysql_packet_set_seq_id(packet, seq_id)
				n, err = mysqlConn.NetConn.Write(packet)
			}
			log.Infof("send %v: %v", key, n)
			if mysql_packet_get_cmd(packet) == COM_STMT_CLOSE {
				stmt_id = 0
			}
		}
		//		if mysql_packet_get_cmd(packet) == COM_STMT_PREPARE {
		mysqlConn.NetConn.SetReadDeadline(time.Now().Add(time.Second))
		//		} else {
		//			conn.SetReadDeadline(time.Now())
		//		}
		buf := make([]byte, 65535)
		n, err := mysqlConn.NetConn.Read(buf)
		if err == io.EOF {
			log.Warnf("packet => #v", packet)
			log.Errorf("EOF while reading")
			panic("fuck")
		} else if err != nil {
			log.Warnf("read pack error %v", err)
		} else {
			buf = buf[:n]
			if mysql_packet_get_cmd(packet) == COM_STMT_PREPARE {
				// conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				if int(buf[4]) == 0 {
					stmt_id = binary.LittleEndian.Uint32(buf[5:9])
					log.Warnf("prepare reply, set stmt_id=%d", stmt_id)
				} else {
					log.Errorf("prepare stmt error. packet => %v", string(buf[13:]))
				}
			} else {
				log.Warnf("reply packet len=%d", len(buf))
			}
		}
	}
}

func main() {
	var handle *pcap.Handle
	var err error

	workers = make(map[string]chan []byte)
	reorg_map = make(map[string][]byte)

	if err != nil {
		panic(err)
	}

	if handle, err = pcap.OpenOffline(sourcePcapFile); err != nil {
		panic(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handlePacket(packet) // Do something with a packet
		// time.Sleep * time.Second)
	}

	log.Info("Hello World")
}

func mysql_packet_get_cmd(raw_packet []byte) byte {
	return raw_packet[4]
}

func mysql_packet_set_seq_id(raw_packet []byte, new_id byte) []byte {
	raw_packet[3] = new_id
	return raw_packet
}

func mysql_packet_set_stmt_id(raw_packet []byte, stmt_id uint32) []byte {
	if mysql_packet_get_cmd(raw_packet) == COM_STMT_EXECUTE || mysql_packet_get_cmd(raw_packet) == COM_STMT_CLOSE {
		binary.LittleEndian.PutUint32(raw_packet[5:9], stmt_id)
		return raw_packet
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

	// log.Infof("key => %v", key)
	// log.Infof("%v\n", tcp.Payload)
	if len(tcp.Payload) == 0 || tcp.DstPort != 4000 {
		return
	}
	log.Infof("# %v:%d => %v:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)
	key := fmt.Sprintf("%v:%d->%v:%d", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort)

	data := tcp.Payload
	if old_data, ok := reorg_map[key]; ok {
		data = append(old_data, data...)
	}

	payload_length := mysql_packet_get_payload_length(data)
	cmd := mysql_packet_get_cmd(data)

	payload := data[4:]

	log.Infof("got mysql packet from .pcap cmd=%d  len=%d pkt_len=%d", cmd, payload_length, len(payload))
	if payload_length > len(payload) {
		reorg_map[key] = data
		log.Info("skip and wait for reorg")
		return
	} else if payload_length < len(payload) {
		log.Errorf("should have len %v, have %v", payload_length, len(payload))
		log.Errorf("%v\n", data)
		panic("are you sb?")
	} else {
		delete(reorg_map, key)
	}

	switch cmd {
	case COM_SLEEP, COM_QUIT, COM_PING, COM_FIELD_LIST, 133, 141:

	default:
		if ch, ok := workers[key]; ok {
			ch <- data
		} else {
			new_ch := make(chan []byte, 102400)
			go worker_for_some_ip(key, new_ch)
			workers[key] = new_ch
			new_ch <- data
		}
	}
}

func handleMysqlPacket(packet []byte) {

}
