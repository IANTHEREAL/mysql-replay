package mysql

import (
	"net"
	"time"
)

// Config is a configuration parsed from a DSN string
type Config struct {
	User         string         // Username
	Passwd       string         // Password (requires User)
	Net          string         // Network type
	Addr         string         // Network address (requires Net)
	Collation    string         // Connection collation
	Loc          *time.Location // Location for time.Time values
	Timeout      time.Duration  // Dial timeout
	ReadTimeout  time.Duration  // I/O read timeout
	WriteTimeout time.Duration  // I/O write timeout
}

func Open(netProto, user, passwd, host string) (*MysqlConn, error) {
	var err error

	// New mysqlConn
	mc := &MysqlConn{
		maxWriteSize: maxPacketSize - 1,
	}
	mc.cfg = &Config{
		User:      user,
		Passwd:    passwd,
		Addr:      host,
		Loc:       time.UTC,
		Collation: defaultCollation,
		Net:       netProto,
	}

	mc.parseTime = false
	mc.strict = false

	// Connect to Server
	nd := net.Dialer{Timeout: mc.cfg.Timeout}
	mc.NetConn, err = nd.Dial(mc.cfg.Net, mc.cfg.Addr)
	if err != nil {
		return nil, err
	}

	if tc, ok := mc.NetConn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlive(true); err != nil {
			mc.NetConn.Close()
			mc.NetConn = nil
			return nil, err
		}
	}

	mc.buf = newBuffer(mc.NetConn)

	// Set I/O timeouts
	mc.buf.timeout = mc.cfg.ReadTimeout
	mc.writeTimeout = mc.cfg.WriteTimeout

	// Reading Handshake Initialization Packet
	cipher, err := mc.readInitPacket()
	if err != nil {
		mc.cleanup()
		return nil, err
	}

	// Send Client Authentication Packet
	if err = mc.writeAuthPacket(cipher); err != nil {
		mc.cleanup()
		return nil, err
	}

	// Handle response to auth packet, switch methods if possible
	if err = handleAuthResult(mc, cipher); err != nil {
		mc.cleanup()
		return nil, err
	}

	err = mc.exec("SET NAMES utf8")
	if err != nil {
		mc.Close()
		return nil, err
	}

	return mc, nil
}

func handleAuthResult(mc *MysqlConn, cipher []byte) error {
	// Read Result Packet
	err := mc.readResultOK()
	if err == nil {
		return nil // auth successful
	}

	if mc.cfg == nil {
		return err
	}

	return err
}
