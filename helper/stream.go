package helper

type RPCReader struct {
	recv func() ([]byte, error)
	data []byte
	err  error
}

func NewRPCReader(reader func() ([]byte, error)) *RPCReader {
	return &RPCReader{
		recv: reader,
	}
}

func (r *RPCReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		r.data, r.err = r.recv()
	}

	n := copy(p, r.data)
	r.data = r.data[n:]

	if len(r.data) == 0 {
		return n, r.err
	}

	return n, nil
}

type RPCWriter struct {
	send func([]byte) error
}

func NewRPCWriter(send func([]byte) error) *RPCWriter {
	return &RPCWriter{
		send: send,
	}
}

func (w *RPCWriter) Write(p []byte) (int, error) {
	return len(p), w.send(p)
}
