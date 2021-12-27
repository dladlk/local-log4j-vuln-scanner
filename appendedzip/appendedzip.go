package appendedzip

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
)

// NewReader searches for ZIP beginning-of-file signatures ('P' 'K'
// 03 04) in r and tries to read the file starting at that offset
// using an encryption-enabled archive/zip, returning a *zip.Reader
// for the first valid entry, or an error.
func NewReader(r io.ReaderAt, size int64) (*zip.Reader, error) {
	const BufferSize = 4096
	var buf [BufferSize + 4]byte
	for i := int64(0); (i-1)*BufferSize < size; i++ {
		readSize, err := r.ReadAt(buf[:], i*BufferSize)
		if err != nil && err != io.EOF {
			break
		}

		n := 0
		for {
			m := bytes.Index(buf[n:readSize], []byte("PK\x03\x04"))
			if m == -1 {
				break
			}
			off := i*BufferSize + int64(n+m)
			stopSize := size - off
			sr := io.NewSectionReader(r, off, stopSize)
			if zr, ze := zip.NewReader(sr, stopSize+1); ze == nil {
				return zr, nil
			}
			n += m + 1
		}
		if err == io.EOF {
			break
		}
	}
	return nil, errors.New("no zip file found")
}
