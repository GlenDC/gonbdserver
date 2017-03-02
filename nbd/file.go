package nbd

import (
	"errors"
	"io"
	"os"
	"strconv"

	"golang.org/x/net/context"
)

// FileBackend implements Backend
type FileBackend struct {
	file *os.File
	size uint64
}

// WriteAt implements Backend.WriteAt
func (fb *FileBackend) WriteAt(ctx context.Context, r io.Reader, offset, length int64, fua bool) (int64, error) {
	buffer := make([]byte, length)
	r.Read(buffer)

	n, err := fb.file.WriteAt(buffer, offset)
	if err != nil || !fua {
		return int64(n), err
	}
	err = fb.file.Sync()
	if err != nil {
		return 0, err
	}
	return int64(n), err
}

// ReadAt implements Backend.ReadAt
func (fb *FileBackend) ReadAt(ctx context.Context, w io.Writer, offset, length int64) (int64, error) {
	buffer := make([]byte, length)
	n, err := fb.file.ReadAt(buffer, offset)
	if err != nil {
		return 0, err
	}
	if int64(n) != length {
		return 0, errors.New("wrong size")
	}

	n, err = w.Write(buffer)
	return int64(n), err
}

// TrimAt implements Backend.TrimAt
func (fb *FileBackend) TrimAt(ctx context.Context, offset, length int64) (int64, error) {
	return length, nil
}

// Flush implements Backend.Flush
func (fb *FileBackend) Flush(ctx context.Context) error {
	return nil
}

// Close implements Backend.Close
func (fb *FileBackend) Close(ctx context.Context) error {
	return fb.file.Close()
}

// Geometry implements Backend.Geometry
func (fb *FileBackend) Geometry(ctx context.Context) (uint64, uint64, uint64, uint64, error) {
	return fb.size, 1, 32 * 1024, 128 * 1024 * 1024, nil
}

// HasFua implements Backend.HasFua
func (fb *FileBackend) HasFua(ctx context.Context) bool {
	return true
}

// HasFlush implements Backend.HasFlush
func (fb *FileBackend) HasFlush(ctx context.Context) bool {
	return true
}

// NewFileBackend generates a new file backend
func NewFileBackend(ctx context.Context, ec *ExportConfig) (Backend, error) {
	perms := os.O_RDWR
	if ec.ReadOnly {
		perms = os.O_RDONLY
	}
	if s, _ := strconv.ParseBool(ec.DriverParameters["sync"]); s {
		perms |= os.O_SYNC
	}

	file, err := os.OpenFile(ec.DriverParameters["path"], perms, 0666)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &FileBackend{
		file: file,
		size: uint64(stat.Size()),
	}, nil
}

// Register our backend
func init() {
	RegisterBackend("file", NewFileBackend)
}
