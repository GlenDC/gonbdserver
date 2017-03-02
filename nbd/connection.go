package nbd

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
)

// Map of configuration text to TLS versions
var tlsVersionMap = map[string]uint16{
	"ssl3.0": tls.VersionSSL30,
	"tls1.0": tls.VersionTLS10,
	"tls1.1": tls.VersionTLS11,
	"tls1.2": tls.VersionTLS12,
}

// Map of configuration text to TLS authentication strategies
var tlsClientAuthMap = map[string]tls.ClientAuthType{
	"none":          tls.NoClientCert,
	"request":       tls.RequestClientCert,
	"require":       tls.RequireAnyClientCert,
	"verify":        tls.VerifyClientCertIfGiven,
	"requireverify": tls.RequireAndVerifyClientCert,
}

// ConnectionParameters holds parameters for each inbound connection
type ConnectionParameters struct {
	ConnectionTimeout time.Duration // maximum time to complete negotiation
}

// Connection holds the details for each connection
type Connection struct {
	params             *ConnectionParameters // parameters
	conn               net.Conn              // the connection that is used as the NBD transport
	plainConn          net.Conn              // the unencrypted (original) connection
	tlsConn            net.Conn              // the TLS encrypted connection
	logger             *log.Logger           // a logger
	listener           *Listener             // the listener than invoked us
	export             *Export               // a pointer to the export
	backend            Backend               // the backend implementation
	name               string                // the name of the connection for logging purposes
	disconnectReceived bool                  // true if disconnect has been received
	zeroWriteBuffer    bytes.Buffer          // the buffer used to write zero memory
}

// Backend is an interface implemented by the various backend drivers
type Backend interface {
	WriteAt(ctx context.Context, r io.Reader, length, offset int64, fua bool) (int64, error) // write data to w at offset, with force unit access optional
	ReadAt(ctx context.Context, r io.Writer, length, offset int64) (int64, error)            // read from o b at offset
	TrimAt(ctx context.Context, length, offset int64) (int64, error)                         // trim
	Flush(ctx context.Context) error                                                         // flush
	Close(ctx context.Context) error                                                         // close
	Geometry(ctx context.Context) (uint64, uint64, uint64, uint64, error)                    // size, minimum BS, preferred BS, maximum BS
	HasFua(ctx context.Context) bool                                                         // does the driver support FUA?
	HasFlush(ctx context.Context) bool                                                       // does the driver support flush?
}

// BackendGenerator is a generator function type that generates a backend
type BackendGenerator func(ctx context.Context, e *ExportConfig) (Backend, error)

// backendMap is a map between backends and the generator function for them
var backendMap = make(map[string]BackendGenerator)

// Export contains the details of an export
type Export struct {
	size               uint64 // size in bytes
	minimumBlockSize   uint64 // minimum block size
	preferredBlockSize uint64 // preferred block size
	maximumBlockSize   uint64 // maximum block size
	memoryBlockSize    uint64 // block size for memory chunks
	exportFlags        uint16 // export flags in NBD format
	name               string // name of the export
	description        string // description of the export
	readonly           bool   // true if read only
	tlsonly            bool   // true if only to be served over tls
}

// Request is an internal structure for propagating requests through the channels
type Request struct {
	nbdReq  nbdRequest // the request in nbd format
	nbdRep  nbdReply   // the reply in nbd format
	length  uint64     // the checked length
	offset  uint64     // the checked offset
	reqData [][]byte   // request data (e.g. for a write)
	repData [][]byte   // reply data (e.g. for a read)
	flags   uint64     // our internal flag structure characterizing the request
}

// NewConnection returns a new Connection object
func NewConnection(listener *Listener, logger *log.Logger, conn net.Conn) (*Connection, error) {
	params := &ConnectionParameters{
		ConnectionTimeout: time.Second * 5,
	}
	c := &Connection{
		plainConn: conn,
		listener:  listener,
		logger:    logger,
		params:    params,
	}
	return c, nil
}

// errorCodeFromGolangError translates an error returned by golang
// into an NBD error code used for replies
//
// This function could do with some serious work!
func errorCodeFromGolangError(error) uint32 {
	//  TODO: relate the return value to the given error
	return NBD_EIO
}

// isClosedErr returns true if the error related to use of a closed connection.
//
// this is particularly foul but is used to surpress errors that relate to use of a closed connection. This is because
// they only arise as we ourselves close the connection to get blocking reads/writes to safely terminate, and thus do
// not want to report them to the user as an error
func isClosedErr(err error) bool {
	return strings.HasSuffix(err.Error(), "use of closed network connection") // YUCK!
}

// readRequest reads and validates a request,
// returning nil in case no (valid) request could be read.
func (c *Connection) readRequest() *nbdRequest {
	var req nbdRequest
	if err := binary.Read(c.conn, binary.BigEndian, &req); err != nil {
		if nerr, ok := err.(net.Error); ok {
			if nerr.Timeout() {
				c.logger.Printf("[INFO] Client %s timeout, closing connection", c.name)
				return nil
			}
		}
		if isClosedErr(err) {
			// Don't report this - we closed it
			return nil
		}
		if err == io.EOF {
			c.logger.Printf("[WARN] Client %s closed connection abruptly", c.name)
		} else {
			c.logger.Printf("[ERROR] Client %s could not read request: %s", c.name, err)
		}
		return nil
	}

	if req.NbdRequestMagic != NBD_REQUEST_MAGIC {
		c.logger.Printf("[ERROR] Client %s had bad magic number in request", c.name)
		return nil
	}

	return &req
}

// transmit tries to read a request,
// handles the command and dispatches the reply.
// Returns false in case nothing could be transmitted
func (c *Connection) transmit(ctx context.Context) bool {
	req := c.readRequest()
	if req == nil {
		return false
	}

	// handle req flags
	flags, ok := CmdTypeMap[int(req.NbdCommandType)]
	if !ok {
		c.logger.Printf(
			"[ERROR] Client %s unknown command %d",
			c.name, req.NbdCommandType)
		return false
	}

	if flags&CMDT_SET_DISCONNECT_RECEIVED != 0 {
		c.disconnectReceived = true
		return false
	}

	// offset also previously known as 'addr'
	var length, offset uint64

	if flags&CMDT_CHECK_LENGTH_OFFSET != 0 {
		length = uint64(req.NbdLength)
		offset = req.NbdOffset

		if length <= 0 || length+offset > c.export.size {
			c.logger.Printf("[ERROR] Client %s gave bad offset or length", c.name)
			return false
		}

		if length&(c.export.minimumBlockSize-1) != 0 || offset&(c.export.minimumBlockSize-1) != 0 || length > c.export.maximumBlockSize {
			c.logger.Printf("[ERROR] Client %s gave offset or length outside blocksize paramaters cmd=%d (len=%08x,off=%08x,minbs=%08x,maxbs=%08x)", c.name, req.NbdCommandType, length, offset, c.export.minimumBlockSize, c.export.maximumBlockSize)
			return false
		}
	}

	// WARNING: for now I've removed other flag-related logic,
	// let's see if we need any of it
	// if so we'll have to bring it back

	fua := req.NbdCommandFlags&NBD_CMD_FLAG_FUA != 0

	nbdRep := nbdReply{
		NbdReplyMagic: NBD_REPLY_MAGIC,
		NbdHandle:     req.NbdHandle,
		NbdError:      0,
	}

	if flags&CMDT_CHECK_NOT_READ_ONLY != 0 && c.export.readonly {
		// send the reply back
		if err := binary.Write(c.conn, binary.BigEndian, nbdRep); err != nil {
			c.logger.Printf("[ERROR] Client %s cannot write reply header\n", c.name)
			return false
		}

		return true
	}

	// create a byteBuffer which can be used for writing
	// we can't directly write, as we first need to write the header
	var buffer *bytes.Buffer

	// handle request command
	switch req.NbdCommandType {
	case NBD_CMD_READ:
		length := length // make length local
		// need to write to a byteBuffer, as we can't write directly
		// to the connection, due to having to have to write the header first
		buffer = new(bytes.Buffer)

		for i := 0; length > 0; i++ {
			blocklen := c.export.memoryBlockSize
			if blocklen > length {
				blocklen = length
			}

			// WARNING: potential overflow (blocklen, offset)
			n, err := c.backend.ReadAt(ctx, buffer, int64(blocklen), int64(offset))
			if err != nil {
				c.logger.Printf("[WARN] Client %s got read I/O error: %s", c.name, err)
				nbdRep.NbdError = errorCodeFromGolangError(err)
				break
			} else if uint64(n) != blocklen {
				c.logger.Printf("[WARN] Client %s got incomplete read (%d != %d) at offset %d", c.name, n, length, offset)
				nbdRep.NbdError = NBD_EIO
				break
			}

			offset += blocklen
			length -= blocklen
		}

	case NBD_CMD_WRITE:
		length, offset := length, offset // make length,offset local
		for i := 0; length > 0; i++ {
			blocklen := c.export.memoryBlockSize
			if blocklen > length {
				blocklen = length
			}

			// Previously we would read from a 2D byte slice
			// when `req.flags&CMDT_REQ_PAYLOAD != 0` was true,
			// which was true for these cases.
			// Now we pipe the connection directly into the backend

			// WARNING: potential overflow (blocklen, offset)
			n, err := c.backend.WriteAt(ctx, c.conn, int64(blocklen), int64(offset), fua)
			if err != nil {
				c.logger.Printf("[WARN] Client %s got write I/O error: %s", c.name, err)
				nbdRep.NbdError = errorCodeFromGolangError(err)
				break
			} else if uint64(n) != blocklen {
				c.logger.Printf("[WARN] Client %s got incomplete write (%d != %d) at offset %d", c.name, n, length, offset)
				nbdRep.NbdError = NBD_EIO
				break
			}
			offset += blocklen
			length -= blocklen
		}

	case NBD_CMD_WRITE_ZEROES:
		length, offset := length, offset // make length,offset local
		// Requires us to read zero data
		// Previously a 2D slice buffer was allocated/reused and zero-memoried
		// now we simply make use of the fact that a slice buffer
		// in Golang is automaticly zero-memoried
		c.zeroWriteBuffer.Reset()
		c.zeroWriteBuffer.Grow(int(length))

		for i := 0; length > 0; i++ {
			blocklen := c.export.memoryBlockSize
			if blocklen > length {
				blocklen = length
			}

			// WARNING: potential overflow (blocklen, offset)
			n, err := c.backend.WriteAt(ctx, &c.zeroWriteBuffer,
				int64(blocklen), int64(offset), fua)
			if err != nil {
				c.logger.Printf("[WARN] Client %s got write I/O error: %s", c.name, err)
				nbdRep.NbdError = errorCodeFromGolangError(err)
				break
			} else if uint64(n) != blocklen {
				c.logger.Printf("[WARN] Client %s got incomplete write (%d != %d) at offset %d", c.name, n, length, offset)
				nbdRep.NbdError = NBD_EIO
				break
			}
			offset += blocklen
			length -= blocklen
		}

	case NBD_CMD_FLUSH:
		c.backend.Flush(ctx)

	case NBD_CMD_TRIM:
		length, offset := length, offset // make length,offset local
		for i := 0; length > 0; i++ {
			blocklen := c.export.memoryBlockSize
			if blocklen > length {
				blocklen = length
			}

			// WARNING: potential overflow (length, offset)
			n, err := c.backend.TrimAt(ctx, int64(length), int64(offset))
			if err != nil {
				c.logger.Printf("[WARN] Client %s got trim I/O error: %s", c.name, err)
				nbdRep.NbdError = errorCodeFromGolangError(err)
				break
			} else if uint64(n) != blocklen {
				c.logger.Printf("[WARN] Client %s got incomplete trim (%d != %d) at offset %d", c.name, n, length, offset)
				nbdRep.NbdError = NBD_EIO
				break
			}

			offset += blocklen
			length -= blocklen
		}

	case NBD_CMD_DISC:
		c.logger.Printf("[INFO] Client %s requested disconnect\n", c.name)
		if err := c.backend.Flush(ctx); err != nil {
			c.logger.Printf("[ERROR] Client %s cannot flush backend: %s\n", c.name, err)
		}

		return true

	case NBD_CMD_CLOSE:
		c.logger.Printf("[INFO] Client %s requested close\n", c.name)
		if err := c.backend.Flush(ctx); err != nil {
			c.logger.Printf("[ERROR] Client %s cannot flush backend: %s\n", c.name, err)
		}
		// still need to reply

	default:
		c.logger.Printf("[ERROR] Client %s sent unknown command %d\n",
			c.name, req.NbdCommandType)
		return true // perhaps next command is valid
	}

	// send the reply back
	if err := binary.Write(c.conn, binary.BigEndian, nbdRep); err != nil {
		c.logger.Printf("[ERROR] Client %s cannot write reply header\n", c.name)
		return false
	}

	if flags&CMDT_REP_PAYLOAD != 0 && buffer != nil && buffer.Len() > 0 {
		length := length // make length local

		for length > 0 {
			blocklen := c.export.memoryBlockSize
			if blocklen > length {
				blocklen = length
			}

			// WARNING: potential overflow (blocklen)
			n, err := io.CopyN(c.conn, buffer, int64(blocklen))
			if err != nil {
				c.logger.Printf("[ERROR] Client %s cannot write reply payload: %s\n", c.name, err)
				return false
			}
			// WARNING: potential underflow (n)
			if uint64(n) != blocklen {
				c.logger.Printf("[ERROR] Client %s cannot write reply complete payload: wrote %d bytes instead of %d bytes\n", c.name, n, length)
				return false
			}
			length -= blocklen
		}

		buffer = nil
	}

	return true
}

// Serve the two phases of an NBD connection.
// The first phase is the Negotiation between Server and Client.
// The second phase is the transmition of data, replies based on requests.
func (c *Connection) Serve(parentCtx context.Context) {
	ctx, cancelFunc := context.WithCancel(parentCtx)

	c.conn = c.plainConn
	c.name = c.plainConn.RemoteAddr().String()
	if c.name == "" {
		c.name = "[unknown]"
	}

	defer func() {
		if c.backend != nil {
			c.backend.Close(ctx)
		}
		if c.tlsConn != nil {
			c.tlsConn.Close()
		}

		c.conn.Close()
		cancelFunc()
	}()

	// Phase #1: Negotiation
	if err := c.negotiate(ctx); err != nil {
		c.logger.Printf("[INFO] Negotiation failed with %s: %v", c.name, err)
		return
	}

	c.name = fmt.Sprintf("%s/%s", c.name, c.export.name)
	c.logger.Printf("[INFO] Negotiation succeeded with %s, serving synchronously", c.name)

	// Phase #2: Transmition
	// basically keep reading until we can't any longer
	for c.transmit(ctx) {
	}
}

// skip bytes
func skip(r io.Reader, n uint32) error {
	for n > 0 {
		l := n
		if l > 1024 {
			l = 1024
		}
		b := make([]byte, l)
		if nr, err := io.ReadFull(r, b); err != nil {
			return err
		} else if nr != int(l) {
			return errors.New("skip returned short read")
		}
		n -= l
	}
	return nil
}

// negotiate negotiates a connection
func (c *Connection) negotiate(ctx context.Context) error {
	c.conn.SetDeadline(time.Now().Add(c.params.ConnectionTimeout))

	// We send a newstyle header
	nsh := nbdNewStyleHeader{
		NbdMagic:       NBD_MAGIC,
		NbdOptsMagic:   NBD_OPTS_MAGIC,
		NbdGlobalFlags: NBD_FLAG_FIXED_NEWSTYLE,
	}

	if !c.listener.disableNoZeroes {
		nsh.NbdGlobalFlags |= NBD_FLAG_NO_ZEROES
	}

	if err := binary.Write(c.conn, binary.BigEndian, nsh); err != nil {
		return errors.New("Cannot write magic header")
	}

	// next they send client flags
	var clf nbdClientFlags

	if err := binary.Read(c.conn, binary.BigEndian, &clf); err != nil {
		return errors.New("Cannot read client flags")
	}

	done := false
	// now we get options
	for !done {
		var opt nbdClientOpt
		if err := binary.Read(c.conn, binary.BigEndian, &opt); err != nil {
			return errors.New("Cannot read option (perhaps client dropped the connection)")
		}
		if opt.NbdOptMagic != NBD_OPTS_MAGIC {
			return errors.New("Bad option magic")
		}
		if opt.NbdOptLen > 65536 {
			return errors.New("Option is too long")
		}
		switch opt.NbdOptID {
		case NBD_OPT_EXPORT_NAME, NBD_OPT_INFO, NBD_OPT_GO:
			var name []byte

			clientSupportsBlockSizeConstraints := false

			if opt.NbdOptID == NBD_OPT_EXPORT_NAME {
				name = make([]byte, opt.NbdOptLen)
				n, err := io.ReadFull(c.conn, name)
				if err != nil {
					return err
				}
				if uint32(n) != opt.NbdOptLen {
					return errors.New("Incomplete name")
				}
			} else {
				var numInfoElements uint16
				if err := binary.Read(c.conn, binary.BigEndian, &numInfoElements); err != nil {
					return errors.New("Bad number of info elements")
				}
				for i := uint16(0); i < numInfoElements; i++ {
					var infoElement uint16
					if err := binary.Read(c.conn, binary.BigEndian, &infoElement); err != nil {
						return errors.New("Bad number of info elements")
					}
					switch infoElement {
					case NBD_INFO_BLOCK_SIZE:
						clientSupportsBlockSizeConstraints = true
					}
				}
				var nameLength uint32
				if err := binary.Read(c.conn, binary.BigEndian, &nameLength); err != nil {
					return errors.New("Bad export name length")
				}
				if nameLength > 4096 {
					return errors.New("Name is too long")
				}
				name = make([]byte, nameLength)
				n, err := io.ReadFull(c.conn, name)
				if err != nil {
					return err
				}
				if uint32(n) != nameLength {
					return errors.New("Incomplete name")
				}
				l := 2 + 2*uint32(numInfoElements) + 4 + uint32(nameLength)
				if opt.NbdOptLen > l {
					if err := skip(c.conn, opt.NbdOptLen-l); err != nil {
						return err
					}
				} else if opt.NbdOptLen < l {
					return errors.New("Option length too short")
				}
			}

			if len(name) == 0 {
				name = []byte(c.listener.defaultExport)
			}

			// Next find our export
			ec, err := c.getExportConfig(ctx, string(name))
			if err != nil || (ec.TLSOnly && c.tlsConn == nil) {
				if opt.NbdOptID == NBD_OPT_EXPORT_NAME {
					// we have to just abort here
					if err != nil {
						return err
					}
					return errors.New("Attempt to connect to TLS-only connection without TLS")
				}
				or := nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_ERR_UNKNOWN,
					NbdOptReplyLength: 0,
				}
				if err == nil {
					or.NbdOptReplyType = NBD_REP_ERR_TLS_REQD
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot send info error")
				}
				break
			}

			// Now we know we are going to go with the export for sure
			// any failure beyond here and we are going to drop the
			// connection (assuming we aren't doing NBD_OPT_INFO)
			export, err := c.connectExport(ctx, ec)
			if err != nil {
				if opt.NbdOptID == NBD_OPT_EXPORT_NAME {
					return err
				}
				c.logger.Printf("[INFO] Could not connect client %s to %s: %v", c.name, string(name), err)
				or := nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_ERR_UNKNOWN,
					NbdOptReplyLength: 0,
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot send info error")
				}
				break
			}

			// for the reply
			name = []byte(export.name)
			description := []byte(export.description)

			if opt.NbdOptID == NBD_OPT_EXPORT_NAME {
				// this option has a unique reply format
				ed := nbdExportDetails{
					NbdExportSize:  export.size,
					NbdExportFlags: export.exportFlags,
				}
				if err := binary.Write(c.conn, binary.BigEndian, ed); err != nil {
					return errors.New("Cannot write export details")
				}
			} else {
				// Send NBD_INFO_EXPORT
				or := nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_INFO,
					NbdOptReplyLength: 12,
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot write info export pt1")
				}
				ir := nbdInfoExport{
					NbdInfoType:          NBD_INFO_EXPORT,
					NbdExportSize:        export.size,
					NbdTransmissionFlags: export.exportFlags,
				}
				if err := binary.Write(c.conn, binary.BigEndian, ir); err != nil {
					return errors.New("Cannot write info export pt2")
				}

				// Send NBD_INFO_NAME
				or = nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_INFO,
					NbdOptReplyLength: uint32(2 + len(name)),
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot write info name pt1")
				}
				if err := binary.Write(c.conn, binary.BigEndian, uint16(NBD_INFO_NAME)); err != nil {
					return errors.New("Cannot write name id")
				}
				if err := binary.Write(c.conn, binary.BigEndian, name); err != nil {
					return errors.New("Cannot write name")
				}

				// Send NBD_INFO_DESCRIPTION
				or = nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_INFO,
					NbdOptReplyLength: uint32(2 + len(description)),
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot write info description pt1")
				}
				if err := binary.Write(c.conn, binary.BigEndian, uint16(NBD_INFO_DESCRIPTION)); err != nil {
					return errors.New("Cannot write description id")
				}
				if err := binary.Write(c.conn, binary.BigEndian, description); err != nil {
					return errors.New("Cannot write description")
				}

				// Send NBD_INFO_BLOCK_SIZE
				or = nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_INFO,
					NbdOptReplyLength: 14,
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot write info block size pt1")
				}
				ir2 := nbdInfoBlockSize{
					NbdInfoType:           NBD_INFO_BLOCK_SIZE,
					NbdMinimumBlockSize:   uint32(export.minimumBlockSize),
					NbdPreferredBlockSize: uint32(export.preferredBlockSize),
					NbdMaximumBlockSize:   uint32(export.maximumBlockSize),
				}
				if err := binary.Write(c.conn, binary.BigEndian, ir2); err != nil {
					return errors.New("Cannot write info block size pt2")
				}

				replyType := NBD_REP_ACK

				if export.minimumBlockSize > 1 && !clientSupportsBlockSizeConstraints {
					replyType = NBD_REP_ERR_BLOCK_SIZE_REQD
				}

				// Send ACK or error
				or = nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   replyType,
					NbdOptReplyLength: 0,
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot info ack")
				}
				if opt.NbdOptID == NBD_OPT_INFO || or.NbdOptReplyType&NBD_REP_FLAG_ERROR != 0 {
					// Disassociate the backend as we are not closing
					c.backend.Close(ctx)
					c.backend = nil
					break
				}
			}

			if clf.NbdClientFlags&NBD_FLAG_C_NO_ZEROES == 0 && opt.NbdOptID == NBD_OPT_EXPORT_NAME {
				// send 124 bytes of zeroes.
				zeroes := make([]byte, 124, 124)
				if err := binary.Write(c.conn, binary.BigEndian, zeroes); err != nil {
					return errors.New("Cannot write zeroes")
				}
			}
			c.export = export
			done = true

		case NBD_OPT_LIST:
			for _, e := range c.listener.exports {
				name := []byte(e.Name)
				or := nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_SERVER,
					NbdOptReplyLength: uint32(len(name) + 4),
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot send list item")
				}
				l := uint32(len(name))
				if err := binary.Write(c.conn, binary.BigEndian, l); err != nil {
					return errors.New("Cannot send list name length")
				}
				if n, err := c.conn.Write(name); err != nil || n != len(name) {
					return errors.New("Cannot send list name")
				}
			}
			or := nbdOptReply{
				NbdOptReplyMagic:  NBD_REP_MAGIC,
				NbdOptID:          opt.NbdOptID,
				NbdOptReplyType:   NBD_REP_ACK,
				NbdOptReplyLength: 0,
			}
			if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
				return errors.New("Cannot send list ack")
			}
		case NBD_OPT_STARTTLS:
			if c.listener.tlsconfig == nil || c.tlsConn != nil {
				// say it's unsuppported
				c.logger.Printf("[INFO] Rejecting upgrade of connection with %s to TLS", c.name)
				or := nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_ERR_UNSUP,
					NbdOptReplyLength: 0,
				}
				if c.tlsConn != nil { // TLS is already negotiated
					or.NbdOptReplyType = NBD_REP_ERR_INVALID
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot reply to unsupported TLS option")
				}
			} else {
				or := nbdOptReply{
					NbdOptReplyMagic:  NBD_REP_MAGIC,
					NbdOptID:          opt.NbdOptID,
					NbdOptReplyType:   NBD_REP_ACK,
					NbdOptReplyLength: 0,
				}
				if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
					return errors.New("Cannot send TLS ack")
				}
				c.logger.Printf("[INFO] Upgrading connection with %s to TLS", c.name)
				// switch over to TLS
				tls := tls.Server(c.conn, c.listener.tlsconfig)
				c.tlsConn = tls
				c.conn = tls
				// explicitly handshake so we get an error here if there is an issue
				if err := tls.Handshake(); err != nil {
					return fmt.Errorf("TLS handshake failed: %s", err)
				}
			}
		case NBD_OPT_ABORT:
			or := nbdOptReply{
				NbdOptReplyMagic:  NBD_REP_MAGIC,
				NbdOptID:          opt.NbdOptID,
				NbdOptReplyType:   NBD_REP_ACK,
				NbdOptReplyLength: 0,
			}
			if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
				return errors.New("Cannot send abort ack")
			}
			return errors.New("Connection aborted by client")
		default:
			// eat the option
			if err := skip(c.conn, opt.NbdOptLen); err != nil {
				return err
			}
			// say it's unsuppported
			or := nbdOptReply{
				NbdOptReplyMagic:  NBD_REP_MAGIC,
				NbdOptID:          opt.NbdOptID,
				NbdOptReplyType:   NBD_REP_ERR_UNSUP,
				NbdOptReplyLength: 0,
			}
			if err := binary.Write(c.conn, binary.BigEndian, or); err != nil {
				return errors.New("Cannot reply to unsupported option")
			}
		}
	}

	c.conn.SetDeadline(time.Time{})
	return nil
}

// getExport generates an export for a given name
func (c *Connection) getExportConfig(ctx context.Context, name string) (*ExportConfig, error) {
	for _, ec := range c.listener.exports {
		if ec.Name == name {
			return &ec, nil
		}
	}
	return nil, errors.New("No such export")
}

// round a uint64 up to the next power of two
func roundUpToNextPowerOfTwo(x uint64) uint64 {
	var r uint64 = 1
	for i := 0; i < 64; i++ {
		if x <= r {
			return r
		}
		r = r << 1
	}
	return 0 // won't fit in uint64 :-(
}

// connectExport generates an export for a given name, and connects to it using the chosen backend
func (c *Connection) connectExport(ctx context.Context, ec *ExportConfig) (*Export, error) {
	// defaults to false in case of error,
	// this is good enough for our purposes
	forceFlush, _ := strconv.ParseBool(ec.DriverParameters["flush"])
	forceFua, _ := strconv.ParseBool(ec.DriverParameters["fua"])

	backendgen, ok := backendMap[strings.ToLower(ec.Driver)]
	if !ok {
		return nil, fmt.Errorf("No such driver %s", ec.Driver)
	}

	backend, err := backendgen(ctx, ec)
	if err != nil {
		return nil, err
	}

	size, minimumBlockSize, preferredBlockSize, maximumBlockSize, err := backend.Geometry(ctx)
	if err != nil {
		backend.Close(ctx)
		return nil, err
	}
	if c.backend != nil {
		c.backend.Close(ctx)
	}
	c.backend = backend
	if ec.MinimumBlockSize != 0 {
		minimumBlockSize = ec.MinimumBlockSize
	}
	if ec.PreferredBlockSize != 0 {
		preferredBlockSize = ec.PreferredBlockSize
	}
	if ec.MaximumBlockSize != 0 {
		maximumBlockSize = ec.MaximumBlockSize
	}
	if minimumBlockSize == 0 {
		minimumBlockSize = 1
	}
	minimumBlockSize = roundUpToNextPowerOfTwo(minimumBlockSize)
	preferredBlockSize = roundUpToNextPowerOfTwo(preferredBlockSize)
	// ensure preferredBlockSize is a multiple of the minimum block size
	preferredBlockSize = preferredBlockSize & ^(minimumBlockSize - 1)
	if preferredBlockSize < minimumBlockSize {
		preferredBlockSize = minimumBlockSize
	}
	// ensure maximumBlockSize is a multiple of preferredBlockSize
	maximumBlockSize = maximumBlockSize & ^(preferredBlockSize - 1)
	if maximumBlockSize < preferredBlockSize {
		maximumBlockSize = preferredBlockSize
	}

	flags := uint16(NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_WRITE_ZEROES | NBD_FLAG_SEND_CLOSE)
	if backend.HasFua(ctx) || forceFua {
		flags |= NBD_FLAG_SEND_FUA
	}
	if backend.HasFlush(ctx) || forceFlush {
		flags |= NBD_FLAG_SEND_FLUSH
	}

	size = size & ^(minimumBlockSize - 1)
	return &Export{
		size:               size,
		exportFlags:        flags,
		name:               ec.Name,
		readonly:           ec.ReadOnly,
		tlsonly:            ec.TLSOnly,
		description:        ec.Description,
		minimumBlockSize:   minimumBlockSize,
		preferredBlockSize: preferredBlockSize,
		maximumBlockSize:   maximumBlockSize,
		memoryBlockSize:    preferredBlockSize,
	}, nil
}

// RegisterBackend allows you to register a backend with a name,
// overwriting any existing backend for that name
func RegisterBackend(name string, generator BackendGenerator) {
	backendMap[name] = generator
}

// GetBackendNames returns the names of all registered backends
func GetBackendNames() []string {
	b := make([]string, len(backendMap))
	i := 0
	for k := range backendMap {
		b[i] = k
		i++
	}
	sort.Strings(b)
	return b
}
