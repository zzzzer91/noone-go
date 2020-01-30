package buffer

import "io"

type ReadWriter interface {
	ReadFrom(r io.Reader) (int, error)
	WriteTo(w io.Writer) (int, error)
}

type ctx struct {
	data   []byte
	offset int
	length int
}

func New(cap int) *ctx {
	return &ctx{
		data: make([]byte, cap),
	}
}

func (c *ctx) Reset() {
	c.offset = 0
	c.length = 0
}

func (c *ctx) ReadFrom(r io.Reader) (int, error) {
	n, err := r.Read(c.data[c.offset+c.length:])
	if err != nil {
		return 0, err
	}
	c.length += n
	return n, nil
}

func (c *ctx) WriteTo(w io.Writer) (int, error) {
	n, err := w.Write(c.data[c.offset : c.offset+c.length])
	if err != nil {
		return 0, err
	}
	c.offset += n
	c.length -= n
	if c.length == 0 {
		c.Reset()
	}
	return n, nil
}
