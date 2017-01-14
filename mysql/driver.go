package mysql

import (
	"net"
	"strings"
	"time"

	"github.com/juju/errors"
)

// Config is a configuration parsed from a DSN string
type Config struct {
	User         string         // Username
	Passwd       string         // Password (requires User)
	Net          string         // Network type
	Addr         string         // Network address (requires Net)
	DBName       string         // Database name
	Collation    string         // Connection collation
	Loc          *time.Location // Location for time.Time values
	Timeout      time.Duration  // Dial timeout
	ReadTimeout  time.Duration  // I/O read timeout
	WriteTimeout time.Duration  // I/O write timeout
}

func Open(dsn string) (*MysqlConn, error) {
	var err error

	// New mysqlConn
	mc := &MysqlConn{
		maxWriteSize: maxPacketSize - 1,
	}
	mc.cfg, err = ParseDSN(dsn)
	if err != nil {
		return nil, err
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

// ParseDSN parses the DSN string to a Config
func ParseDSN(dsn string) (cfg *Config, err error) {
	// New config with some default values
	cfg = &Config{
		Loc:       time.UTC,
		Collation: defaultCollation,
	}

	// [user[:password]@][net[(addr)]]/dbname[?param1=value1&paramN=valueN]
	// Find the last '/' (since the password or the net addr might contain a '/')
	foundSlash := false
	for i := len(dsn) - 1; i >= 0; i-- {
		if dsn[i] == '/' {
			foundSlash = true
			var j, k int

			// left part is empty if i <= 0
			if i > 0 {
				// [username[:password]@][protocol[(address)]]
				// Find the last '@' in dsn[:i]
				for j = i; j >= 0; j-- {
					if dsn[j] == '@' {
						// username[:password]
						// Find the first ':' in dsn[:j]
						for k = 0; k < j; k++ {
							if dsn[k] == ':' {
								cfg.Passwd = dsn[k+1 : j]
								break
							}
						}
						cfg.User = dsn[:k]

						break
					}
				}

				// [protocol[(address)]]
				// Find the first '(' in dsn[j+1:i]
				for k = j + 1; k < i; k++ {
					if dsn[k] == '(' {
						// dsn[i-1] must be == ')' if an address is specified
						if dsn[i-1] != ')' {
							if strings.ContainsRune(dsn[k+1:i], ')') {
								return nil, errors.New("invalid DSN: did you forget to escape a param value?")
							}
							return nil, errors.New("invalid DSN: network address not terminated (missing closing brace)")
						}
						cfg.Addr = dsn[k+1 : i-1]
						break
					}
				}
				cfg.Net = dsn[j+1 : k]
			}

			// dbname[?param1=value1&...&paramN=valueN]
			// Find the first '?' in dsn[i+1:]
			for j = i + 1; j < len(dsn); j++ {
				if dsn[j] == '?' {
					break
				}
			}
			cfg.DBName = dsn[i+1 : j]

			break
		}
	}

	if !foundSlash && len(dsn) > 0 {
		return nil, errors.New("invalid DSN: missing the slash separating the database name")
	}

	// Set default network if empty
	if cfg.Net == "" {
		cfg.Net = "tcp"
	}

	// Set default address if empty
	if cfg.Addr == "" {
		switch cfg.Net {
		case "tcp":
			cfg.Addr = "127.0.0.1:3306"
		case "unix":
			cfg.Addr = "/tmp/mysql.sock"
		default:
			return nil, errors.New("default addr for network '" + cfg.Net + "' unknown")
		}

	}

	return
}
