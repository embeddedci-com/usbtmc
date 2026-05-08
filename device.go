// Copyright (c) 2015-2026 The usbtmc developers. All rights reserved.
// Project site: https://github.com/gotmc/usbtmc
// Use of this source code is governed by a MIT-style license that
// can be found in the LICENSE.txt file for the project.

package usbtmc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/gotmc/usbtmc/driver"
)

const (
	// This is a guess. The USB spec says the max value can be fetched from
	// the descriptor, but the libusb documentation says packets can be up
	// to 512 bytes.
	// Ref: https://libusb.sourceforge.io/api-1.0/libusb_packetoverflow.html
	maxPacketSize = 512

	usbtmcHeaderLen = 12
)

// Device models a USBTMC device, which includes a USB device and the required
// USBTMC attributes and methods.
type Device struct {
	mu              sync.Mutex
	usbDevice       driver.USBDevice
	bTag            byte
	termChar        byte
	termCharEnabled bool
}

// Write creates the appropriate USBMTC header, writes the header and data on
// the bulk out endpoint, and returns the number of bytes written and any
// errors.
func (d *Device) Write(p []byte) (n int, err error) {
	return d.WriteBinary(context.Background(), p)
}

// WriteBinary writes binary data without adding a terminator. It creates the
// appropriate USBTMC header, writes the header and data on the bulk out
// endpoint, and returns the number of bytes written and any errors.
func (d *Device) WriteBinary(ctx context.Context, p []byte) (n int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// FIXME(mdr): I need to change this so that I look at the size of the buf
	// being written to see if it can truly fit into one transfer, and if not
	// split it into multiple transfers.
	maxTransferSize := 512
	for pos := 0; pos < len(p); {
		if err := ctx.Err(); err != nil {
			return pos, err
		}
		d.bTag = nextbTag(d.bTag)
		thisLen := len(p[pos:])
		if thisLen > maxTransferSize-bulkOutHeaderSize {
			thisLen = maxTransferSize - bulkOutHeaderSize
		}
		isLastChunk := pos+thisLen >= len(p)
		header := encodeBulkOutHeader(d.bTag, uint32(thisLen), isLastChunk)
		data := append(header[:], p[pos:pos+thisLen]...)
		if moduloFour := len(data) % 4; moduloFour > 0 {
			numAlignment := 4 - moduloFour
			alignment := bytes.Repeat([]byte{0x00}, numAlignment)
			data = append(data, alignment...)
		}
		_, err := d.usbDevice.WriteContext(ctx, data)
		if err != nil {
			return pos, err
		}
		pos += thisLen
	}
	return len(p), nil
}

// doRead creates and sends the header on the bulk out endpoint and then reads
// from the bulk in endpoint per USBTMC standard.
//
// USBTMC §3.3.1: a logical message-in transaction may consist of MULTIPLE
// DEV_DEP_MSG_IN responses. The host sends one REQUEST_DEV_DEP_MSG_IN, the
// device replies with a DEV_DEP_MSG_IN whose header carries an EOM bit. If
// EOM=0, the host MUST send another REQUEST_DEV_DEP_MSG_IN to receive the
// next chunk; the device discards any pending data otherwise. (Rigol DS1000Z
// firmware exhibits this exact behavior on long :WAV:DATA? responses, where
// the first reply caps at one bulk-IN packet and EOM is unset until the final
// chunk.)
func (d *Device) doRead(ctx context.Context, p []byte, useTermChar bool) (n int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	pos := 0
	for pos < len(p) {
		if err := ctx.Err(); err != nil {
			return pos, err
		}

		// Send REQUEST_DEV_DEP_MSG_IN for the remaining capacity. Each
		// USBTMC message-in response is paired with its own request.
		d.bTag = nextbTag(d.bTag)
		remaining := uint32(len(p) - pos) //nolint:gosec
		header := encodeMsgInBulkOutHeader(d.bTag, remaining,
			useTermChar && d.termCharEnabled, d.termChar)
		if _, werr := d.usbDevice.WriteContext(ctx, header[:]); werr != nil {
			return pos, werr
		}
		debug.Printf("sent reqdevdepmsgin hdr %v (msg pos %d, buf left %d)\n",
			hex.EncodeToString(header[:]), pos, remaining)

		// Drain one DEV_DEP_MSG_IN response. It may span multiple libusb
		// bulk-in transfers (terminated by short packet or ZLP). The first
		// transfer carries the 12-byte USBTMC header (and EOM bit);
		// follow-up transfers within the SAME message carry raw data.
		//
		// libusb may return more bytes than the device's TransferSize
		// promised because the response is padded to a USB packet boundary;
		// per-iteration we cap so padding bytes don't leak into the caller's
		// buffer (alignment bytes are trailing garbage, e.g. "\\" or "^").
		msgStart := pos
		var transfer int
		var transferAttr byte
		first := true
		for {
			if pos >= len(p) {
				break
			}
			if err := ctx.Err(); err != nil {
				return pos, err
			}
			var resp int
			var rerr error
			if first {
				resp, transfer, transferAttr, rerr = d.readRemoveHeader(ctx, d.bTag, p[pos:])
				first = false
			} else {
				resp, rerr = d.readKeepHeader(ctx, p[pos:])
			}
			debug.Printf("read: pos %d (buf left %d); got %d bytes (transfer=%d EOM=%d)",
				pos, len(p[pos:]), resp, transfer, transferAttr&1)

			dumpLen, dumpTrunc := 100, 1
			if resp < dumpLen {
				dumpLen, dumpTrunc = resp, 0
			}
			if left := len(p) - pos; left < dumpLen {
				dumpLen, dumpTrunc = left, 0
			}
			debug.Printf("data[%d:]=%s%s\n", pos,
				hex.EncodeToString(p[pos:pos+dumpLen]),
				[]string{"", "..."}[dumpTrunc])

			if rerr != nil {
				return pos, rerr
			}
			if resp == 0 {
				debug.Print("zero-length read; end of this DEV_DEP_MSG_IN")
				break
			}
			// Discard any libusb-level alignment padding past the device's
			// declared TransferSize for this DEV_DEP_MSG_IN message.
			msgGot := pos - msgStart
			if msgGot+resp > transfer {
				resp = transfer - msgGot
			}
			pos += resp
			if pos-msgStart >= transfer {
				// Got the full DEV_DEP_MSG_IN payload the device promised
				// in the header; check EOM below to decide whether to
				// issue another REQUEST.
				break
			}
		}

		// EOM=1 -> entire logical message is done. EOM=0 -> issue another
		// REQUEST_DEV_DEP_MSG_IN to drain the remainder of this logical
		// message (the loop's next iteration handles that).
		if (transferAttr & 1) == 1 {
			break
		}
		// Safety: no progress on this iteration. Avoid an infinite loop
		// in case the device returns an empty DEV_DEP_MSG_IN with EOM=0.
		if pos == msgStart {
			break
		}
	}

	return pos, nil
}

// Read reads from the device respecting the termChar setting. Use for transfers
// of ASCII data.
func (d *Device) Read(p []byte) (n int, err error) {
	return d.doRead(context.Background(), p, true)
}

// ReadBinary reads binary data without terminator interpretation.
func (d *Device) ReadBinary(ctx context.Context, p []byte) (n int, err error) {
	return d.doRead(ctx, p, false)
}

// ReadRaw reads from the device without allowing termChar to be set. Use for
// transfers of binary data.
func (d *Device) ReadRaw(p []byte) (n int, err error) {
	return d.ReadBinary(context.Background(), p)
}

func inHdrToString(buf []byte) string {
	id, bTag, bTagInverse := msgID(buf[0]), buf[1], buf[2]

	out := "type "
	switch id {
	case devDepMsgOut:
		out += "1???" // no response expected
	case devDepMsgIn:
		out += "dvdp"
	case vendorSpecificOut:
		out += "126?" // no response expected
	case vendorSpecificIn:
		out += "vnsp"
	default:
		out += fmt.Sprintf("R%03d", id)
	}

	out += fmt.Sprintf(" tag % 3d", bTag)
	if invertbTag(bTag) != bTagInverse {
		out += fmt.Sprintf(" bad inv % 3d", bTagInverse)
	}

	if msgID(id) == devDepMsgIn {
		out += fmt.Sprintf(" sz %d", binary.LittleEndian.Uint32(buf[4:8]))

		attr := buf[8]
		out += fmt.Sprintf(" D1=%d", (attr&2)>>1)
		out += fmt.Sprintf(" EOM?=%s", []string{"no", "yes"}[(attr&1)])

		out += " " + hex.EncodeToString(buf[9:12])
	} else {
		out += " " + hex.EncodeToString(buf[4:12])
	}

	return out
}

func (d *Device) readRemoveHeader(
	ctx context.Context, expectedBTag byte, p []byte,
) (n int, transfer int, transferAttr byte, err error) {
	// Reading from the USB device triggers interactions with the hardware,
	// so we take care with the buffer size. The caller expects len(p)
	// bytes, but we also need to allow space for the USBTMC header. The
	// libusb documentation is full of dire warnings about what happens if
	// the incoming data exceeds the receiving buffer[^1]. It recommends
	// making sure the incoming buffer is a multiple of the maximum packet
	// size. We don't know the actual maximum packet size, but we think we
	// know the maximum packet size, so rounding the transfer size up to the
	// next multiple of the maximum packet size should make it difficult for
	// incoming data to overflow.
	//
	// [^1]: https://libusb.sourceforge.io/api-1.0/libusb_packetoverflow.html
	tempSz := len(p) + usbtmcHeaderLen
	if m := tempSz % 512; m != 0 {
		tempSz += 512 - m
	}

	debug.Printf("readRemoveHeader: len(p) %v, w/hdr %v -> buf size %v\n",
		len(p), len(p)+usbtmcHeaderLen, tempSz)
	temp := make([]byte, tempSz)

	n, err = d.usbDevice.ReadContext(ctx, temp)
	if err != nil {
		return 0, 0, 0, err
	}
	if n < usbtmcHeaderLen {
		return 0, 0, 0, fmt.Errorf(
			"short %d-byte read: no space for header", n)
	}

	debug.Printf("readRemoveHeader: header %s\n", inHdrToString(temp))

	// Validate the response header per USBTMC Table 5.
	respMsgID := msgID(temp[0])
	if respMsgID != devDepMsgIn {
		return 0, 0, 0, fmt.Errorf(
			"unexpected MsgID: got %d, want %d (DEV_DEP_MSG_IN)",
			respMsgID, devDepMsgIn)
	}
	respBTag := temp[1]
	if respBTag != expectedBTag {
		return 0, 0, 0, fmt.Errorf(
			"bTag mismatch: got %d, want %d", respBTag, expectedBTag)
	}
	if temp[2] != invertbTag(respBTag) {
		return 0, 0, 0, fmt.Errorf(
			"bTagInverse mismatch: got %d, want %d",
			temp[2], invertbTag(respBTag))
	}

	t32 := binary.LittleEndian.Uint32(temp[4:8])
	transfer = int(t32)
	transferAttr = temp[8]

	// Copy the bytes after the reader to the caller's buffer, but only as
	// many bytes as the USB device said it read. Let the caller deal with
	// any discrepancies between the USBTMC transfer size and the number of
	// bytes we got from the USB device.
	toCopy := min(len(temp)-usbtmcHeaderLen, n-usbtmcHeaderLen)
	if toCopy > 0 {
		copy(p, temp[usbtmcHeaderLen:usbtmcHeaderLen+toCopy])
	}
	return n - usbtmcHeaderLen, transfer, transferAttr, nil
}

func (d *Device) readKeepHeader(ctx context.Context, p []byte) (n int, err error) {
	return d.usbDevice.ReadContext(ctx, p)
}

// Close closes the underlying USB device.
func (d *Device) Close() error {
	return d.usbDevice.Close()
}

// WriteString writes a string using the underlying USB device. A newline
// terminator is not automatically added.
func (d *Device) WriteString(s string) (n int, err error) {
	return d.Write([]byte(s))
}

// WriteStringContext is like WriteString but accepts a context.
func (d *Device) WriteStringContext(ctx context.Context, s string) (n int, err error) {
	return d.WriteBinary(ctx, []byte(s))
}

// Command sends the SCPI/ASCII command to the underlying USB device. A newline
// character is automatically added to the end of the string.
func (d *Device) Command(ctx context.Context, format string, a ...any) error {
	cmd := format
	if a != nil {
		cmd = fmt.Sprintf(format, a...)
	}
	_, err := d.WriteStringContext(ctx, strings.TrimSpace(cmd)+string(d.termChar))
	return err
}

// Query writes the given string to the USBTMC device and returns the returned
// value as a string. A newline character is automatically added to the query
// command sent to the instrument.
func (d *Device) Query(ctx context.Context, s string) (string, error) {
	err := d.Command(ctx, s)
	if err != nil {
		return "", err
	}

	// Try to ensure a single-packet read using ASCII mode (with termChar).
	p := make([]byte, maxPacketSize-usbtmcHeaderLen)
	n, err := d.doRead(ctx, p, true)
	if err != nil {
		return "", err
	}
	s = string(p[:n])
	p = nil
	return s, nil
}
