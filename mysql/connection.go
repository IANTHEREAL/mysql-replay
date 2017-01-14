package mysql

import (
	"database/sql/driver"
	"net"
	"time"

	"github.com/ngaut/log"
)

type MysqlConn struct {
	buf          buffer
	NetConn      net.Conn
	affectedRows uint64
	insertId     uint64
	cfg          *Config
	maxWriteSize int
	writeTimeout time.Duration
	flags        clientFlag
	status       statusFlag
	sequence     uint8
	parseTime    bool
	strict       bool
}

func (mc *MysqlConn) Close() (err error) {
	// Makes Close idempotent
	if mc.NetConn != nil {
		err = mc.writeCommandPacket(COM_QUIT)
	}

	mc.cleanup()

	return
}

func (mc *MysqlConn) cleanup() {
	// Makes cleanup idempotent
	if mc.NetConn != nil {
		if err := mc.NetConn.Close(); err != nil {
			log.Error(err)
		}
		mc.NetConn = nil
	}
	mc.cfg = nil
	mc.buf.nc = nil
}

// Internal function to execute commands
func (mc *MysqlConn) exec(query string) error {
	// Send command
	err := mc.writeCommandPacketStr(COM_QUERY, query)
	if err != nil {
		return err
	}

	// Read Result
	resLen, err := mc.readResultSetHeaderPacket()
	if err == nil && resLen > 0 {
		if err = mc.readUntilEOF(); err != nil {
			return err
		}

		err = mc.readUntilEOF()
	}

	return err
}

func (mc *MysqlConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	if mc.NetConn == nil {
		log.Error(ErrInvalidConn)
		return nil, driver.ErrBadConn
	}
	// Send command
	err := mc.writeCommandPacketStr(COM_QUERY, query)
	if err == nil {
		// Read Result
		var resLen int
		resLen, err = mc.readResultSetHeaderPacket()
		if err == nil {
			rows := new(textRows)
			rows.mc = mc

			if resLen == 0 {
				// no columns, no more data
				return emptyRows{}, nil
			}
			// Columns
			rows.columns, err = mc.readColumns(resLen)
			return rows, err
		}
	}
	return nil, err
}
