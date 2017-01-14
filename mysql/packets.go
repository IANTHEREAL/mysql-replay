package mysql

import (
	"bytes"
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/juju/errors"
	"github.com/ngaut/log"
)

// Packets documentation:
// http://dev.mysql.com/doc/internals/en/client-server-protocol.html

// Read packet to buffer 'data'
func (mc *MysqlConn) readPacket() ([]byte, error) {
	var payload []byte
	for {
		// Read packet header
		data, err := mc.buf.readNext(4)
		if err != nil {
			log.Error(err)
			mc.Close()
			return nil, driver.ErrBadConn
		}

		// Packet Length [24 bit]
		pktLen := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)

		if pktLen < 1 {
			log.Error(ErrMalformPkt)
			mc.Close()
			return nil, driver.ErrBadConn
		}

		// Check Packet Sync [8 bit]
		if data[3] != mc.sequence {
			if data[3] > mc.sequence {
				return nil, ErrPktSyncMul
			}
			return nil, ErrPktSync
		}
		mc.sequence++

		// Read packet body [pktLen bytes]
		data, err = mc.buf.readNext(pktLen)
		if err != nil {
			log.Error(err)
			mc.Close()
			return nil, driver.ErrBadConn
		}

		isLastPacket := (pktLen < maxPacketSize)

		// Zero allocations for non-splitting packets
		if isLastPacket && payload == nil {
			return data, nil
		}

		payload = append(payload, data...)

		if isLastPacket {
			return payload, nil
		}
	}
}

// Write packet buffer 'data'
func (mc *MysqlConn) writePacket(data []byte) error {
	pktLen := len(data) - 4

	for {
		var size int
		if pktLen >= maxPacketSize {
			data[0] = 0xff
			data[1] = 0xff
			data[2] = 0xff
			size = maxPacketSize
		} else {
			data[0] = byte(pktLen)
			data[1] = byte(pktLen >> 8)
			data[2] = byte(pktLen >> 16)
			size = pktLen
		}
		data[3] = mc.sequence

		// Write packet
		if mc.writeTimeout > 0 {
			if err := mc.NetConn.SetWriteDeadline(time.Now().Add(mc.writeTimeout)); err != nil {
				return err
			}
		}

		n, err := mc.NetConn.Write(data[:4+size])
		if err == nil && n == 4+size {
			mc.sequence++
			if size != maxPacketSize {
				return nil
			}
			pktLen -= size
			data = data[size:]
			continue
		}

		// Handle error
		if err == nil { // n != len(data)
			log.Error(ErrMalformPkt)
		} else {
			log.Error(err)
		}
		return driver.ErrBadConn
	}
}

// Handshake Initialization Packet
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
func (mc *MysqlConn) readInitPacket() ([]byte, error) {
	data, err := mc.readPacket()
	if err != nil {
		return nil, err
	}

	if data[0] == iERR {
		return nil, mc.handleErrorPacket(data)
	}

	// protocol version [1 byte]
	if data[0] < minProtocolVersion {
		return nil, errors.Errorf(
			"unsupported protocol version %d. Version %d or higher is required",
			data[0],
			minProtocolVersion,
		)
	}

	// server version [null terminated string]
	// connection id [4 bytes]
	pos := 1 + bytes.IndexByte(data[1:], 0x00) + 1 + 4

	// first part of the password cipher [8 bytes]
	cipher := data[pos : pos+8]

	// (filler) always 0x00 [1 byte]
	pos += 8 + 1

	// capability flags (lower 2 bytes) [2 bytes]
	mc.flags = clientFlag(binary.LittleEndian.Uint16(data[pos : pos+2]))
	if mc.flags&clientProtocol41 == 0 {
		return nil, ErrOldProtocol
	}
	pos += 2

	if len(data) > pos {
		// character set [1 byte]
		// status flags [2 bytes]
		// capability flags (upper 2 bytes) [2 bytes]
		// length of auth-plugin-data [1 byte]
		// reserved (all [00]) [10 bytes]
		pos += 1 + 2 + 2 + 1 + 10
		cipher = append(cipher, data[pos:pos+12]...)
		// make a memory safe copy of the cipher slice
		var b [20]byte
		copy(b[:], cipher)
		return b[:], nil
	}

	// make a memory safe copy of the cipher slice
	var b [8]byte
	copy(b[:], cipher)
	return b[:], nil
}

// Client Authentication Packet
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
func (mc *MysqlConn) writeAuthPacket(cipher []byte) error {
	// Adjust client flags based on server support
	clientFlags := clientProtocol41 |
		clientSecureConn |
		clientLongPassword |
		clientTransactions |
		clientLocalFiles |
		clientPluginAuth |
		clientMultiResults |
		mc.flags&clientLongFlag

	// User Password
	scrambleBuff := scramblePassword(cipher, []byte(mc.cfg.Passwd))

	pktLen := 4 + 4 + 1 + 23 + len(mc.cfg.User) + 1 + 1 + len(scrambleBuff) + 21 + 1

	// To specify a db name
	if n := len(mc.cfg.DBName); n > 0 {
		clientFlags |= clientConnectWithDB
		pktLen += n + 1
	}

	// Calculate packet length and get buffer with that size
	data := mc.buf.takeSmallBuffer(pktLen + 4)
	if data == nil {
		// can not take the buffer. Something must be wrong with the connection
		log.Error(ErrBusyBuffer)
		return driver.ErrBadConn
	}

	// ClientFlags [32 bit]
	data[4] = byte(clientFlags)
	data[5] = byte(clientFlags >> 8)
	data[6] = byte(clientFlags >> 16)
	data[7] = byte(clientFlags >> 24)

	// MaxPacketSize [32 bit] (none)
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x00

	// Charset [1 byte]
	var found bool
	data[12], found = collations[mc.cfg.Collation]
	if !found {
		// Note possibility for false negatives:
		// could be triggered  although the collation is valid if the
		// collations map does not contain entries the server supports.
		return errors.New("unknown collation")
	}

	// Filler [23 bytes] (all 0x00)
	pos := 13
	for ; pos < 13+23; pos++ {
		data[pos] = 0
	}

	// User [null terminated string]
	if len(mc.cfg.User) > 0 {
		pos += copy(data[pos:], mc.cfg.User)
	}
	data[pos] = 0x00
	pos++

	// ScrambleBuffer [length encoded integer]
	data[pos] = byte(len(scrambleBuff))
	pos += 1 + copy(data[pos+1:], scrambleBuff)

	// Databasename [null terminated string]
	if len(mc.cfg.DBName) > 0 {
		pos += copy(data[pos:], mc.cfg.DBName)
		data[pos] = 0x00
		pos++
	}

	// Assume native client during response
	pos += copy(data[pos:], "mysql_native_password")
	data[pos] = 0x00

	// Send Auth packet
	return mc.writePacket(data)
}

//  Client clear text authentication packet
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchResponse
func (mc *MysqlConn) writeClearAuthPacket() error {
	// Calculate the packet length and add a tailing 0
	pktLen := len(mc.cfg.Passwd) + 1
	data := mc.buf.takeSmallBuffer(4 + pktLen)
	if data == nil {
		// can not take the buffer. Something must be wrong with the connection
		log.Error(ErrBusyBuffer)
		return driver.ErrBadConn
	}

	// Add the clear password [null terminated string]
	copy(data[4:], mc.cfg.Passwd)
	data[4+pktLen-1] = 0x00

	return mc.writePacket(data)
}

func (mc *MysqlConn) writeCommandPacket(command byte) error {
	// Reset Packet Sequence
	mc.sequence = 0

	data := mc.buf.takeSmallBuffer(4 + 1)
	if data == nil {
		// can not take the buffer. Something must be wrong with the connection
		log.Error(ErrBusyBuffer)
		return driver.ErrBadConn
	}

	// Add command byte
	data[4] = command

	// Send CMD packet
	return mc.writePacket(data)
}

func (mc *MysqlConn) writeCommandPacketStr(command byte, arg string) error {
	// Reset Packet Sequence
	mc.sequence = 0

	pktLen := 1 + len(arg)
	data := mc.buf.takeBuffer(pktLen + 4)
	if data == nil {
		// can not take the buffer. Something must be wrong with the connection
		log.Error(ErrBusyBuffer)
		return driver.ErrBadConn
	}

	// Add command byte
	data[4] = command

	// Add arg
	copy(data[5:], arg)

	// Send CMD packet
	return mc.writePacket(data)
}

// Returns error if Packet is not an 'Result OK'-Packet
func (mc *MysqlConn) readResultOK() error {
	data, err := mc.readPacket()
	if err == nil {
		// packet indicator
		switch data[0] {

		case iOK:
			return mc.handleOkPacket(data)

		case iEOF:
			if len(data) > 1 {
				plugin := string(data[1:bytes.IndexByte(data, 0x00)])
				if plugin == "mysql_old_password" {
					// using old_passwords
					return ErrOldPassword
				} else if plugin == "mysql_clear_password" {
					// using clear text password
					return ErrCleartextPassword
				} else {
					return ErrUnknownPlugin
				}
			} else {
				return ErrOldPassword
			}

		default: // Error otherwise
			return mc.handleErrorPacket(data)
		}
	}
	return err
}

// Result Set Header Packet
// http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::Resultset
func (mc *MysqlConn) readResultSetHeaderPacket() (int, error) {
	data, err := mc.readPacket()
	if err == nil {
		switch data[0] {

		case iOK:
			return 0, mc.handleOkPacket(data)

		case iERR:
			return 0, mc.handleErrorPacket(data)

		case iLocalInFile:
			return 0, mc.handleInFileRequest(string(data[1:]))
		}

		// column count
		num, _, n := readLengthEncodedInteger(data)
		if n-len(data) == 0 {
			return int(num), nil
		}

		return 0, ErrMalformPkt
	}
	return 0, err
}

// Error Packet
// http://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-ERR_Packet
func (mc *MysqlConn) handleErrorPacket(data []byte) error {
	if data[0] != iERR {
		return ErrMalformPkt
	}

	// 0xff [1 byte]

	// Error Number [16 bit uint]
	errno := binary.LittleEndian.Uint16(data[1:3])

	pos := 3

	// SQL State [optional: # + 5bytes string]
	if data[3] == 0x23 {
		//sqlstate := string(data[4 : 4+5])
		pos = 9
	}

	// Error Message [string]
	return &MySQLError{
		Number:  errno,
		Message: string(data[pos:]),
	}
}

func readStatus(b []byte) statusFlag {
	return statusFlag(b[0]) | statusFlag(b[1])<<8
}

// Ok Packet
// http://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-OK_Packet
func (mc *MysqlConn) handleOkPacket(data []byte) error {
	var n, m int

	// 0x00 [1 byte]

	// Affected rows [Length Coded Binary]
	mc.affectedRows, _, n = readLengthEncodedInteger(data[1:])

	// Insert id [Length Coded Binary]
	mc.insertId, _, m = readLengthEncodedInteger(data[1+n:])

	// server_status [2 bytes]
	mc.status = readStatus(data[1+n+m : 1+n+m+2])
	if err := mc.discardResults(); err != nil {
		return err
	}

	// warning count [2 bytes]
	if !mc.strict {
		return nil
	}

	pos := 1 + n + m + 2
	if binary.LittleEndian.Uint16(data[pos:pos+2]) > 0 {
		return mc.getWarnings()
	}
	return nil
}

// Read Packets as Field Packets until EOF-Packet or an Error appears
// http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition41
func (mc *MysqlConn) readColumns(count int) ([]mysqlField, error) {
	columns := make([]mysqlField, count)

	for i := 0; ; i++ {
		data, err := mc.readPacket()
		if err != nil {
			return nil, err
		}

		// EOF Packet
		if data[0] == iEOF && (len(data) == 5 || len(data) == 1) {
			if i == count {
				return columns, nil
			}
			return nil, fmt.Errorf("column count mismatch n:%d len:%d", count, len(columns))
		}

		// Catalog
		pos, err := skipLengthEncodedString(data)
		if err != nil {
			return nil, err
		}

		// Database [len coded string]
		n, err := skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		n, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		// Original table [len coded string]
		n, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		pos += n

		// Name [len coded string]
		name, _, n, err := readLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}
		columns[i].name = string(name)
		pos += n

		// Original name [len coded string]
		n, err = skipLengthEncodedString(data[pos:])
		if err != nil {
			return nil, err
		}

		// Filler [uint8]
		// Charset [charset, collation uint8]
		// Length [uint32]
		pos += n + 1 + 2 + 4

		// Field type [uint8]
		columns[i].fieldType = data[pos]
		pos++

		// Flags [uint16]
		columns[i].flags = fieldFlag(binary.LittleEndian.Uint16(data[pos : pos+2]))
		pos += 2

		// Decimals [uint8]
		columns[i].decimals = data[pos]
		//pos++

		// Default value [len coded binary]
		//if pos < len(data) {
		//	defaultVal, _, err = bytesToLengthCodedBinary(data[pos:])
		//}
	}
}

// Reads Packets until EOF-Packet or an Error appears. Returns count of Packets read
func (mc *MysqlConn) readUntilEOF() error {
	for {
		data, err := mc.readPacket()
		if err != nil {
			return err
		}

		switch data[0] {
		case iERR:
			return mc.handleErrorPacket(data)
		case iEOF:
			if len(data) == 5 {
				mc.status = readStatus(data[3:])
			}
			return nil
		}
	}
}

func (mc *MysqlConn) discardResults() error {
	for mc.status&statusMoreResultsExists != 0 {
		resLen, err := mc.readResultSetHeaderPacket()
		if err != nil {
			return err
		}
		if resLen > 0 {
			// columns
			if err := mc.readUntilEOF(); err != nil {
				return err
			}
			// rows
			if err := mc.readUntilEOF(); err != nil {
				return err
			}
		} else {
			mc.status &^= statusMoreResultsExists
		}
	}
	return nil
}
