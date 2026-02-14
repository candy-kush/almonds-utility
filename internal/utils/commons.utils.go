package utils

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/skip2/go-qrcode"

	"almonds-utility/internal/models"
)

type CommonUtils struct{}

func NewCommonUtils() *CommonUtils {
	return &CommonUtils{}
}

func (c *CommonUtils) SecureRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func (c *CommonUtils) GenerateTicketPDF(data *models.TicketRequest) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)

	// Header
	pdf.Cell(40, 10, "Event Ticket: "+data.EventName)
	pdf.Ln(12)

	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Booking ID: %s", data.BookingID))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Location: %s", data.Location))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Date: %s", data.EventDate))
	pdf.Ln(8)
	pdf.Cell(40, 10, fmt.Sprintf("Total Persons: %d", data.TotalPerson))
	pdf.Ln(20)

	// QR Codes Section
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Tickets:")
	pdf.Ln(10)

	for _, qr := range data.QRCodes {
		// 1. Generate QR Bytes
		qrBytes, err := c.GenerateQRImage(qr.QRCode, 256)
		if err == nil {
			// 2. Embed Image options object
			opt := gofpdf.ImageOptions{
				ImageType: "PNG",
				ReadDpi:   true,
			}
			// 3. Register image in PDF from memory
			reader := bytes.NewReader(qrBytes)
			imageName := qr.QRCode // specific key for this image
			_ = pdf.RegisterImageOptionsReader(imageName, opt, reader)

			pdf.ImageOptions(imageName, 10, pdf.GetY(), 30, 30, false, opt, 0, "")
			pdf.SetX(50)
			pdf.Cell(40, 30, "Ticket For: "+qr.TicketFor)
			pdf.Ln(35)
		}
	}

	var buf bytes.Buffer
	err := pdf.Output(&buf)
	return buf.Bytes(), err
}

func (c *CommonUtils) BuildPDFFileName(filepathOriginal, bookingId string) string {

	validFileName := regexp.MustCompile(`^[a-zA-Z0-9._\- ]+$`)

	sanitize := func(name string) string {
		name = strings.TrimSpace(name)

		if name == "" {
			return ""
		}

		// Remove directory traversal
		name = filepath.Base(name)

		// Limit length
		if len(name) > 50 {
			name = name[:50]
		}

		// Validate allowed characters
		if !validFileName.MatchString(name) {
			return ""
		}

		return name
	}

	// 1️⃣ Try original filename
	if sanitized := sanitize(filepathOriginal); sanitized != "" {

		if !strings.HasSuffix(strings.ToLower(sanitized), ".pdf") {
			sanitized += ".pdf"
		}

		return sanitized
	}

	// 2️⃣ Try bookingId
	if sanitized := sanitize(bookingId); sanitized != "" {
		return sanitized + ".pdf"
	}

	// 3️⃣ Fallback → current unix millis
	return strconv.FormatInt(time.Now().UnixMilli(), 10) + ".pdf"
}

// GenerateQRImage returns PNG bytes for a string
func (c *CommonUtils) GenerateQRImage(content string, size int) ([]byte, error) {
	if content == "" {
		return nil, errors.New("content is empty")
	}
	return qrcode.Encode(content, qrcode.High, size)
}

func (c *CommonUtils) ReadRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (c *CommonUtils) GenerateRandomURLSafe(length int) (string, error) {

	byteLen := int(math.Ceil(float64(length) * 3 / 4))
	
	buf, err := c.SecureRandomBytes(byteLen)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buf)[:length], nil
}

func (c *CommonUtils) GenerateRandomBase64(length int) (string, error) {

	byteLen := int(math.Ceil(float64(length) * 3 / 4))

	buf, err := c.SecureRandomBytes(byteLen)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf)[:length], nil
}

func (c *CommonUtils) GenerateRandomHex(length int) (string, error) {

	buf, err := c.SecureRandomBytes((length + 1) / 2)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf)[:length], nil
}


func (c *CommonUtils) RandomStringFromCharset(length int, charset string) (string, error) {

	if charset == "" {
		return "", errors.New("Charset empty")
	}

	result := make([]byte, length)
	max := big.NewInt(int64(len(charset)))

	for i := range length {

		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}

		result[i] = charset[n.Int64()]
	}

	return string(result), nil
}

func (c *CommonUtils) NormalizePlaintext(raw json.RawMessage) (string, error) {

	// Try to unmarshal as string first
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		// It was a JSON string
		return str, nil
	}

	// Otherwise, treat it as JSON object/array and stringify it
	var obj any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", err
	}

	normalized, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	return string(normalized), nil
}

func (c *CommonUtils) ComputeHMAC(data []byte, key []byte) []byte {
	h := hmac.New(crypto.SHA256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func (c *CommonUtils) DecodeByType(value string, valueType string) ([]byte, error) {
	switch strings.ToLower(valueType) {
	case "plain":
		return []byte(value), nil
	case "base64":
		return base64.StdEncoding.DecodeString(value)
	case "hex":
		return hex.DecodeString(value)
	default:
		return nil, errors.New("invalid encoding type")
	}
}

func (c *CommonUtils) Pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func (c *CommonUtils) Pkcs5Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("Invalid padding size")
	}

	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("Invalid padding")
	}

	return data[:length-padding], nil
}