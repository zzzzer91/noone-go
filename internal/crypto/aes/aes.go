package aes

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
)

const (
	IvLen = aes.BlockSize
)

func GenRandomIv(iv []byte) error {
	if len(iv) != IvLen {
		return errors.New("invalid IV length")
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	return nil
}
