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
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

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

// Sentinel errors emitted by readRemoveHeader for response framing problems.
// Exposed via errors.Is so doRead can treat them as recoverable on continuation
// reads (USBTMC §3.3.1) when a device echoes a stale bTag in its bookkeeping
// header — observed on Rigol DS1102Z-E firmware 00.06.04.
var (
	errUSBTMCMsgIDMismatch   = errors.New("unexpected MsgID")
	errUSBTMCBTagMismatch    = errors.New("bTag mismatch")
	errUSBTMCBTagInvMismatch = errors.New("bTagInverse mismatch")
)

func isContinuationHeaderMismatch(err error) bool {
	return errors.Is(err, errUSBTMCBTagMismatch) ||
		errors.Is(err, errUSBTMCMsgIDMismatch) ||
		errors.Is(err, errUSBTMCBTagInvMismatch)
}

// Device models a USBTMC device, which includes a USB device and the required
// USBTMC attributes and methods.
type Device struct {
	mu              sync.Mutex
	usbDevice       driver.USBDevice
	bTag            byte
	termChar        byte
	termCharEnabled bool

	// Debug, if non-nil, receives a one-line summary of every doRead
	// iteration (REQUEST + first response). Useful when troubleshooting
	// firmware quirks; complements the package-level debug logger gated
	// on USBTMC_DEBUG which produces much more verbose output.
	Debug io.Writer
}

func (d *Device) debugf(format string, args ...any) {
	if d.Debug == nil {
		return
	}
	fmt.Fprintf(d.Debug, format, args...)
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
// USBTMC §3.3.1 allows a logical message-in transaction to span multiple
// DEV_DEP_MSG_IN responses, each kicked by its own REQUEST_DEV_DEP_MSG_IN.
// We loop until we see EOM=1, the caller's buffer is full, or the device
// stops making progress. On a continuation read, some firmwares (Rigol
// DS1102Z-E 00.06.04) reply with a bookkeeping packet that echoes the
// previous bTag and then queue the rest of the payload as raw bulk-IN
// packets without a USBTMC header; we recognise that pattern and switch
// the rest of that iteration to header-less reads.
func (d *Device) doRead(ctx context.Context, p []byte, useTermChar bool) (n int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	pos := 0
	initial := true
	iter := 0
	for {
		iter++
		d.bTag = nextbTag(d.bTag)
		header := encodeMsgInBulkOutHeader(d.bTag, uint32(len(p)-pos), //nolint:gosec
			useTermChar && d.termCharEnabled, d.termChar)
		if _, err = d.usbDevice.WriteContext(ctx, header[:]); err != nil {
			return pos, err
		}
		debug.Printf("sent reqdevdepmsgin hdr %v (data len %v)\n",
			hex.EncodeToString(header[:]), len(p)-pos)

		// Per Figure 4 in the USBTMC spec, messages may be sent in multiple
		// transfers. The first will have a USBTMC header, the middle transfers
		// will only contain data bytes, and the final may end with alignment
		// bytes. Mixed in with this are three definitions of length:
		//
		//   1) the number of bytes the caller wants to receive (len(p))
		//   2) the number of bytes the device means to send ('transfer', from
		//      the USBTMC header)
		//   3) the number of bytes in the current transfer (resp).
		//
		// The header also includes an end-of-message (EOM) bit, but it's not
		// clear how this bit is used.
		//
		// We'll attempt to read the number of bytes the caller wants (1), but
		// will stop short if the number of bytes the device wants to send (2)
		// is reached or if it sends a transfer with zero non-header bytes.
		msgStart := pos
		var transfer int
		var transferAttr byte
		// headerOK flips false if a non-initial REQUEST gets back a
		// stale-bTag bookkeeping header (USBTMC §3.3.1 firmware quirk);
		// the rest of this iteration then drains raw bulk-IN packets
		// without expecting another USBTMC header.
		headerOK := true
		// continuation tracks bytes appended via readKeepHeader after the
		// initial readRemoveHeader; logged once per iteration instead of
		// per-packet so a typical :WAV:DATA? read produces ~3 lines of
		// output rather than ~20.
		continuation := 0
		mismatch := false
		for pos < len(p) {
			if err := ctx.Err(); err != nil {
				return pos, err
			}
			var resp int
			var err error
			if pos == msgStart && headerOK {
				resp, transfer, transferAttr, err = d.readRemoveHeader(ctx, d.bTag, p[pos:])
				if err != nil && !initial && isContinuationHeaderMismatch(err) {
					debug.Printf("continuation header mismatch (USBTMC §3.3.1 quirk, tolerated): %v", err)
					headerOK = false
					mismatch = true
					// The bookkeeping packet was consumed by libusb; the
					// payload (if any) follows in subsequent raw packets.
					resp, err = d.readKeepHeader(ctx, p[pos:])
				}
			} else {
				resp, err = d.readKeepHeader(ctx, p[pos:])
				continuation += resp
			}
			debug.Printf("read: pos %d (buf left %d); got %d bytes",
				pos, len(p[pos:]), resp)

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

			if err != nil {
				return pos, err
			}
			if resp == 0 {
				debug.Print("zero-length read; giving up")
				break
			}
			pos += resp
			if headerOK && pos-msgStart >= transfer {
				break
			}
		}
		// On the first iteration, opportunistically drain trailing bulk-IN
		// packets. Some firmwares (Rigol DS1102Z-E 00.06.04) ship the full
		// response in reply to REQUEST 1 but lie in the header — they
		// declare a small `transfer` (e.g. 500 bytes) with EOM=0, then queue
		// the rest of the actual response as raw bulk-IN packets. We've
		// just stopped the protocol-level inner loop at the (untrusted)
		// transfer boundary; check whether more is queued. Use a short
		// timeout so compliant devices, which won't have anything queued
		// past `transfer`, don't hang waiting for non-existent data.
		trailing := 0
		if initial && headerOK && pos < len(p) {
			drainCtx, cancel := context.WithTimeout(ctx, trailingDrainTimeout)
			for pos < len(p) {
				if err := drainCtx.Err(); err != nil {
					break
				}
				r, e := d.readKeepHeader(drainCtx, p[pos:])
				if e != nil {
					// Most likely LIBUSB_ERROR_TIMEOUT — compliant device,
					// nothing more queued. Treat as end-of-stream.
					break
				}
				if r == 0 {
					break
				}
				pos += r
				trailing += r
			}
			cancel()
		}
		// One-line per-iteration summary; complements the much more verbose
		// log produced by USBTMC_DEBUG=1 in debug.go.
		d.debugf("usbtmc: iter=%d transfer=%d EOM=%d cont=%d trail=%d mismatch=%v pos=%d\n",
			iter, transfer, transferAttr&0x01, continuation, trailing, mismatch, pos)
		if headerOK && trailing == 0 {
			if got := pos - msgStart; got > transfer {
				pos = msgStart + transfer
			}
		}
		// Stop if: we tolerated a continuation framing mismatch (the
		// device's framing is unreliable, don't kick again); EOM=1; the
		// caller's buffer is full; the iteration made no progress; or the
		// trailing drain pulled extra bytes — that's a strong signal the
		// declared transfer/EOM was a lie and another REQUEST would either
		// restart the transfer or come back with a stale-bTag bookkeeping
		// packet (also Rigol-quirk territory).
		if !headerOK || transferAttr&0x01 != 0 || pos >= len(p) || pos == msgStart || trailing > 0 {
			break
		}
		initial = false
	}

	return pos, nil
}

// trailingDrainTimeout caps how long the post-protocol drain on the first
// iteration waits for additional bulk-IN data. Sized so quirky firmwares
// (Rigol DS1102Z-E observed at sub-millisecond per packet) have plenty of
// margin while compliant devices don't pay an annoying latency penalty.
const trailingDrainTimeout = 200 * time.Millisecond

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
			"%w: got %d, want %d (DEV_DEP_MSG_IN)",
			errUSBTMCMsgIDMismatch, respMsgID, devDepMsgIn)
	}
	respBTag := temp[1]
	if respBTag != expectedBTag {
		return 0, 0, 0, fmt.Errorf(
			"%w: got %d, want %d",
			errUSBTMCBTagMismatch, respBTag, expectedBTag)
	}
	if temp[2] != invertbTag(respBTag) {
		return 0, 0, 0, fmt.Errorf(
			"%w: got %d, want %d",
			errUSBTMCBTagInvMismatch, temp[2], invertbTag(respBTag))
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
