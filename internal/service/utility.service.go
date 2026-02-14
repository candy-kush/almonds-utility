package service

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/big"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/hkdf"

	"almonds-utility/internal/database"
	"almonds-utility/internal/models"
	"almonds-utility/internal/utils"
)

type UtilityService struct{
	Utils *utils.CommonUtils
	mySql *database.MySQLClient
	cache *cache.Cache
}

func NewUtilityService(mySql *database.MySQLClient, cache *cache.Cache) *UtilityService {
	return &UtilityService{
		mySql: mySql,
		cache: cache,
	}
}


func (s *UtilityService) GeneratePDF(ctx context.Context, req models.PDFRequest) ([]byte, string, error) {
	slog.InfoContext(ctx, "Inside GeneratePDF service method")
	if req.Input == nil {
		slog.InfoContext(ctx, "Missing input data")
		return nil, "", errors.New("Missing input data")
	}

	pdfBytes, err := s.Utils.GenerateTicketPDF(req.Input)
	if err != nil {
		slog.InfoContext(ctx, "error occured in GenerateTicketPDF", "error", err.Error())
		return nil, "", err
	}

	filename := s.Utils.BuildPDFFileName(req.Filename, req.Input.BookingID)
	slog.InfoContext(ctx, "returning from GenerateTicketPDF service method", "filename", filename)

	return pdfBytes, filename, nil
}


func (s *UtilityService) GenerateQR(ctx context.Context, req models.QRRequest) ([]byte, error) {
	slog.InfoContext(ctx, "Inside GenerateQR service method")

	if !strings.EqualFold(req.ExportType, "QR_IMAGE") {
		slog.InfoContext(ctx, "Unsupported export type", "exportType", req.ExportType)
		return nil, errors.New("Unsupported export type")
	}
	
	if !slices.Contains([]string{"png", "jpg", "jpeg"}, strings.ToLower(req.ImageExtension)) {
		slog.InfoContext(ctx, "Unsupported image format", "ImageExtension", req.ImageExtension)
		return nil, errors.New("Unsupported image format, use 'png' or 'jpe' or 'jpeg'")
	}

	if req.Content == "" {
		slog.InfoContext(ctx, "Input required")
		return nil, errors.New("Input required")
	}

	size := 256
	if req.Size > 0 {
		size = req.Size
	}

	slog.InfoContext(ctx, "returning from GenerateQR service method")
	return s.Utils.GenerateQRImage(req.Content, size)
}


func (s *UtilityService) GenerateKeyIVPair(ctx context.Context, keyBytes int, ivBytes int, encoding string) (*models.KeyIVResponse, error) {
	slog.InfoContext(ctx, "Inside GenerateKeyIVPair service method")

	key, _ := s.Utils.ReadRandomBytes(keyBytes)
	iv, _ := s.Utils.ReadRandomBytes(ivBytes)

	var encodedKey, encodedIv string 
	if strings.EqualFold(encoding, "base64") {
		encodedKey = base64.StdEncoding.EncodeToString(key)
		encodedIv = base64.StdEncoding.EncodeToString(iv)
	} else {
		encodedKey = strings.ToUpper(hex.EncodeToString(key))
		encodedIv = strings.ToUpper(hex.EncodeToString(iv))
	}

	slog.InfoContext(ctx, "returning from GenerateKeyIVPair service method", "encodedKey", encodedKey, "encodedIv", encodedIv)
	return &models.KeyIVResponse{
		Key: encodedKey,
		IV:  encodedIv,
	}, nil
}


func encodeULID(data []byte) string {
    var result [26]byte
    
    var buffer uint64
    var bits uint
    pos := 0

    for _, b := range data {
        // Shift existing buffer left by 8 and add new byte
        buffer = (buffer << 8) | uint64(b)
        bits += 8

        // Extract as many 5-bit chunks as possible
        for bits >= 5 {
            idx := (buffer >> (bits - 5)) & 31
            result[pos] = utils.CROCKFORD_BASE32[idx]
            pos++
            bits -= 5
        }
    }

    if bits > 0 {
        idx := (buffer << (5 - bits)) & 31
        result[pos] = utils.CROCKFORD_BASE32[idx]
        pos++
    }

    return string(result[:pos])
}

func (s *UtilityService) GenerateUUID(ctx context.Context, uuidType, version string) (*models.UUIDResponse, error) {
	slog.InfoContext(ctx, "Inside GenerateUUID service method")
	
	var uuidVal string = uuid.NewString()
	switch uuidType {
		case "uuid": {
			if version == "v7" {
				id, _ := uuid.NewV7()
				uuidVal = id.String()
			}
		}

		case "ulid": {
			ts := time.Now().UnixMilli()

			buf := make([]byte, 16)

			buf[0] = byte(ts >> 40)
			buf[1] = byte(ts >> 32)
			buf[2] = byte(ts >> 24)
			buf[3] = byte(ts >> 16)
			buf[4] = byte(ts >> 8)
			buf[5] = byte(ts)

			if _, err := rand.Read(buf[6:]); err != nil {
				uuidVal = ""
			} else {
				uuidVal = encodeULID(buf)
			}
		}
	}

	slog.InfoContext(ctx, "returning from GenerateUUID service method", "uuidVal", uuidVal)

	return &models.UUIDResponse{
		UUID: uuidVal,
	}, nil
}


func (s *UtilityService) GeneratePassword(ctx context.Context, req models.PasswordRequest) (*models.PasswordResponse, error) {
	slog.InfoContext(ctx, "Inside GeneratePassword service method")
	
	if req.Length == 0 {
		req.Length = 8
	}

	typeSets := []string{}

	Small := utils.DefaultPasswordCharset.SMALL
	Big := utils.DefaultPasswordCharset.BIG
	Number := utils.DefaultPasswordCharset.NUMBER
	Special := utils.DefaultPasswordCharset.SPECIAL

	if req.SmallChars {
		typeSets = append(typeSets, Small)
	}
	if req.BigChars {
		typeSets = append(typeSets, Big)
	}
	if req.Numbers {
		typeSets = append(typeSets, Number)
	}
	if req.SpecialChars {
		typeSets = append(typeSets, Special)
	}

	if len(typeSets) == 0 {
		slog.InfoContext(ctx, "No characters selected")
		return nil, errors.New("No characters selected")
	}

	password := make([]byte, req.Length)

	for i := 0; i < req.Length; i++ {
		set := typeSets[i%len(typeSets)]
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		password[i] = set[n.Int64()]
	}

	data, _ := s.CalculateEntropy(ctx, req.Length, len(Small)+len(Big)+len(Number)+len(Special), "")

	slog.InfoContext(ctx, "returning from GeneratePassword service method")
	return &models.PasswordResponse{
		Password: string(password),
		Strength: data.Entropy,
	}, nil
}


func (s *UtilityService) HashWithKey(ctx context.Context, req models.HashRequest) (*models.HashResponse, error) {
	slog.InfoContext(ctx, "Inside HashWithKey service method")

	data := req.Data
	secret := req.Secret
	algo := req.Algo
	outputFormat := strings.ToLower(req.OutputFormat)

	if outputFormat == "" {
		outputFormat = "hex"
	}

	slog.InfoContext(ctx, "", "outputFormat", outputFormat)
	var hmacAlgorithms = map[string]crypto.Hash{
		"sha256":   crypto.SHA256,
		"sha512":   crypto.SHA512,
		"sha384":   crypto.SHA384,
		"sha224":   crypto.SHA224,
		"sha1":     crypto.SHA1,
		"md5":      crypto.MD5,
		"sha3_256": crypto.SHA3_256,
		"sha3_512": crypto.SHA3_512,
	}

	hashType, ok := hmacAlgorithms[strings.ToLower(algo)]
	if !ok || !hashType.Available() {
		slog.InfoContext(ctx, "Unsupported algorithm")
		return nil, errors.New("Unsupported algorithm")
	}

	mac := hmac.New(hashType.New, []byte(secret))
	mac.Write([]byte(data))

	rawHash := mac.Sum(nil)

	var encodedHash string

	switch outputFormat {
		case "hex": {
			encodedHash = strings.ToUpper(hex.EncodeToString(rawHash))
		}

		case "base64": {
			encodedHash = base64.StdEncoding.EncodeToString(rawHash)
		}

		case "base64url": {
			encodedHash = base64.RawURLEncoding.EncodeToString(rawHash)
		}

		default: {
			slog.InfoContext(ctx, "Unsupported outputFormat")
			return nil, errors.New("Unsupported outputFormat: use 'hex' or 'base64' or 'base64url'")
		}
	}
	
	slog.InfoContext(ctx, "returning from HashWithKey service method", "encodedHash", encodedHash)
	return &models.HashResponse{
		Algorithm: strings.ToUpper(algo),
		Hash:      encodedHash,
	}, nil
}


func (s *UtilityService) CollisionProbability(ctx context.Context, length, charsetSize, count int, characterset string) (*models.CollisionResponse, error) {
	slog.InfoContext(ctx, "Inside CollisionProbability service method")

	if length <= 0 || count <= 0 {
		return &models.CollisionResponse{Probability: 0}, nil
	}

	if charsetSize <= 1 {
		return &models.CollisionResponse{Probability: 1}, nil
	}

	// precision = 256 bits
	prec := uint(256)

	k := new(big.Float).SetPrec(prec).SetFloat64(float64(count))

	// log(N) = length * log(charsetSize)
	logCharset := math.Log(float64(charsetSize))
	logN := float64(length) * logCharset

	slog.InfoContext(ctx, "", "logCharset", logCharset, "logN", logN)

	// compute exponent = -(k²)/(2N)
	kSquared := new(big.Float).Mul(k, k)
	two := big.NewFloat(2).SetPrec(prec)

	slog.InfoContext(ctx, "", "kSquared", kSquared, "two", two)

	// denom = 2 * exp(logN)
	expN := math.Exp(logN)
	denom := new(big.Float).Mul(two, new(big.Float).SetFloat64(expN))

	ratio := new(big.Float).Quo(kSquared, denom)
	ratio.Neg(ratio)

	slog.InfoContext(ctx, "", "expN", expN, "denom", denom, "ratio", ratio)

	ratioFloat, _ := ratio.Float64()

	prob := 1 - math.Exp(ratioFloat)

	slog.InfoContext(ctx, "", "ratioFloat", ratioFloat, "probability", prob)

	if prob < 0 {
		prob = 0
	}
	if prob > 1 {
		prob = 1
	}

	slog.InfoContext(ctx, "returning from CollisionProbability service method")
	return &models.CollisionResponse{
		Probability: prob,
	}, nil
}


func (s *UtilityService) CalculateEntropy(ctx context.Context, length, charsetSize int, characterset string) (*models.EntropyResponse, error) {
	slog.InfoContext(ctx, "Inside CalculateEntropy service method")
	
	if characterset != "" {

		runeCount := utf8.RuneCountInString(characterset)
		if runeCount == 0 {
			return &models.EntropyResponse{Entropy: 0}, nil
		}

		frequency := make(map[rune]int)		
		for _, r := range characterset {
			frequency[r]++
		}

		slog.InfoContext(ctx, "", "runeCount", runeCount, "frequency", frequency)

		var entropy float64
		total := float64(runeCount)

		for _, count := range frequency {
			p := float64(count) / total
			entropy += -p * math.Log2(p)
		}

		entropy = entropy * total

		slog.InfoContext(ctx, "returning from CalculateEntropy service method", "entropy", entropy)

		return &models.EntropyResponse{
			Entropy: math.Round(entropy*100) / 100,
		}, nil
	}

	if length <= 0 || charsetSize <= 1 {
		return &models.EntropyResponse{Entropy: 0}, nil
	}

	entropy := float64(length) * math.Log2(float64(charsetSize))

	slog.InfoContext(ctx, "returning from CalculateEntropy service method", "entropy", entropy)

	return &models.EntropyResponse{
		Entropy: math.Round(entropy*100) / 100,
	}, nil
}


func (s *UtilityService) EncryptAES(ctx context.Context, req models.EncryptRequest) (*models.EncryptResponse, error) {
	slog.InfoContext(ctx, "Inside EncryptAES service method")

	// Normalize plaintext
	normalized, err := s.Utils.NormalizePlaintext(req.Plaintext)
	if err != nil {
		return nil, err
	}
	
	slog.InfoContext(ctx, "", "normalized", normalized)

	plaintext := []byte(normalized)

	// Decode secret key
	key, err := s.Utils.DecodeByType(req.SecretKey, req.SecretKeyType)
	if err != nil {
		slog.InfoContext(ctx, "Decoding failed in DecodeByType SecretKey", "error", err)
		return nil, err
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		slog.InfoContext(ctx, "Invalid AES key length")
		return nil, errors.New("Invalid AES key length (must be 16, 24, or 32 bytes)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		slog.InfoContext(ctx, "Exception in creating aes.NewCipher", "error", err)
		return nil, err
	}

	var ciphertext []byte
	var iv []byte

	switch strings.ToLower(req.Mode) {

		case "gcm": {

			slog.InfoContext(ctx, "Handling GCM mode of encryption")

			if req.EnableHMAC {
				slog.InfoContext(ctx, "HMAC not allowed in GCM mode")
				return nil, errors.New("HMAC not allowed in GCM mode (GCM is already authenticated)")
			}

			gcm, err := cipher.NewGCM(block)
			if err != nil {
				slog.InfoContext(ctx, "Exception in creating cipher.NewGCM", "error", err)
				return nil, err
			}

			if req.IV != "" {
				iv, err = s.Utils.DecodeByType(req.IV, req.IVType)
				if err != nil {
					slog.InfoContext(ctx, "Decoding failed in DecodeByType IV", "error", err)
					return nil, err
				}

				if len(iv) != gcm.NonceSize() {
					slog.InfoContext(ctx, "Invalid IV length for GCM")
					return nil, errors.New("Invalid IV length for GCM")
				}

				ciphertext = gcm.Seal(nil, iv, plaintext, nil)

			} else {
				iv = make([]byte, gcm.NonceSize())
				if _, err := rand.Read(iv); err != nil {
					return nil, err
				}

				encrypted := gcm.Seal(nil, iv, plaintext, nil)

				// Embed IV
				payload := make([]byte, 0, len(iv)+len(encrypted))
				payload = append(payload, iv...)
				payload = append(payload, encrypted...)

				ciphertext = payload
			}
		}

		case "cbc": {

			slog.InfoContext(ctx, "Handling CBC mode of encryption")

			blockSize := block.BlockSize()

			if req.IV != "" {
				iv, err = s.Utils.DecodeByType(req.IV, req.IVType)
				if err != nil {
					slog.InfoContext(ctx, "Decoding failed in DecodeByType IV")
					return nil, err
				}

				if len(iv) != blockSize {
					slog.InfoContext(ctx, "Invalid IV length for CBC")
					return nil, errors.New("Invalid IV length for CBC")
				}
			} else {
				iv = make([]byte, blockSize)
				if _, err := rand.Read(iv); err != nil {
					return nil, err
				}
			}

			paddingMode := strings.ToLower(req.Padding)

			switch paddingMode {

				case "", "pkcs5": {
					plaintext = s.Utils.Pkcs5Pad(plaintext, blockSize)
				}

				case "none": {
					if len(plaintext)%blockSize != 0 {
						slog.InfoContext(ctx, "Plaintext must be multiple of block size when padding is 'none'")
						return nil, errors.New("Plaintext must be multiple of block size when padding is 'none'")
					}
				}

				default: {
					slog.InfoContext(ctx, "Unsupported padding type (use pkcs5 or none)")
					return nil, errors.New("Unsupported padding type (use pkcs5 or none)")
				}
			}

			mode := cipher.NewCBCEncrypter(block, iv)
			encrypted := make([]byte, len(plaintext))
			mode.CryptBlocks(encrypted, plaintext)

			// Build payload
			var payload []byte

			if req.IV != "" {
				// External IV mode
				payload = encrypted
			} else {
				// Internal IV mode → embed
				payload = make([]byte, 0, len(iv)+len(encrypted))
				payload = append(payload, iv...)
				payload = append(payload, encrypted...)
			}

			// HMAC
			if req.EnableHMAC {

				if req.HMACKey == "" {
					slog.InfoContext(ctx, "HMAC enabled but no hmacKey provided")
					return nil, errors.New("HMAC enabled but no hmacKey provided")
				}

				macKey, err := s.Utils.DecodeByType(req.HMACKey, req.HMACKeyType)
				if err != nil {
					slog.InfoContext(ctx, "Decoding failed in DecodeByType HMACKey", "error", err)
					return nil, err
				}

				if len(macKey) < 32 {
					slog.InfoContext(ctx, "HMAC key must be at least 32 bytes")
					return nil, errors.New("HMAC key must be at least 32 bytes")
				}

				var macInput []byte

				if req.IV != "" {
					// External IV mode
					macInput = make([]byte, 0, len(iv)+len(payload))
					macInput = append(macInput, iv...)
					macInput = append(macInput, payload...)
				} else {
					// Embedded IV mode
					macInput = payload
				}

				tag := s.Utils.ComputeHMAC(macInput, macKey)

				payload = append(payload, tag...)
			}

			ciphertext = payload
		}

		default: {
			slog.InfoContext(ctx, "Unsupported mode of encryption")
			return nil, errors.New("Unsupported mode (use gcm or cbc)")
		}
	}

	slog.InfoContext(ctx, "ciphertext generated, encoding in required output format", "ciphertext", ciphertext)

	var output string
	switch strings.ToLower(req.OutputFormat) {
		case "base64": {
			output = base64.StdEncoding.EncodeToString(ciphertext)
		}
		case "hex": {
			output = hex.EncodeToString(ciphertext)
		}
		case "base64url": {
			output = base64.RawURLEncoding.EncodeToString(ciphertext)
		}
		default: {
			slog.InfoContext(ctx, "Output format not supported")
			return nil, errors.New("Output format not supported, use 'hex' or 'base64' or 'base64url'")
		}
	}

	slog.InfoContext(ctx, "returning from EncryptAES service method", "output", output)

	return &models.EncryptResponse{
		Ciphertext: output,
	}, nil
}


func (s *UtilityService) DecryptAES(ctx context.Context, req models.DecryptRequest) (*models.DecryptResponse, error) {
	slog.InfoContext(ctx, "Inside DecryptAES service method")

	var data []byte
	var err error

	switch strings.ToLower(req.InputFormat) {
		case "base64": {
			data, err = base64.StdEncoding.DecodeString(req.Ciphertext)
		}
		case "hex": {
			data, err = hex.DecodeString(req.Ciphertext)
		}
		case "base64url": {
			data, err = base64.URLEncoding.DecodeString(req.Ciphertext)
		}
		default: {
			slog.InfoContext(ctx, "Invalid inputFormat")
			return nil, errors.New("Invalid inputFormat (base64 | hex | base64url)")
		}
	}

	if err != nil {
		slog.InfoContext(ctx, "Exception in decoding given ciphertext", "error", err)
		return nil, err
	}

	key, err := s.Utils.DecodeByType(req.SecretKey, req.SecretKeyType)
	if err != nil {
		slog.InfoContext(ctx, "Exception in DecodeByType SecretKey", "error", err)
		return nil, err
	}

	// Strict AES key validation
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		slog.InfoContext(ctx, "Invalid AES key length")
		return nil, errors.New("Invalid AES key length (must be 16, 24, or 32 bytes)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		slog.InfoContext(ctx, "Exception in creating aes.NewCipher", "error", err)
		return nil, err
	}

	var plaintext []byte

	switch strings.ToLower(req.Mode) {

		case "gcm": {

			slog.InfoContext(ctx, "Handling GCM mode of decryption")

			gcm, err := cipher.NewGCM(block)
			if err != nil {
				slog.InfoContext(ctx, "Exception in creating cipher.NewGCM", "error", err)
				return nil, err
			}

			nonceSize := gcm.NonceSize()

			var iv []byte
			var ciphertext []byte

			if req.IV != "" {
				// External IV required
				iv, err = s.Utils.DecodeByType(req.IV, req.IVType)
				if err != nil {
					slog.InfoContext(ctx, "Exception in DecodeByType IV", "error", err)
					return nil, err
				}

				if len(iv) != nonceSize {
					slog.InfoContext(ctx, "Invalid IV length for GCM")
					return nil, errors.New("Invalid IV length for GCM")
				}

				ciphertext = data

			} else {
				// Embedded IV required
				if len(data) < nonceSize {
					slog.InfoContext(ctx, "Ciphertext too short")
					return nil, errors.New("Ciphertext too short")
				}

				iv = data[:nonceSize]
				ciphertext = data[nonceSize:]
			}

			plain, err := gcm.Open(nil, iv, ciphertext, nil)
			if err != nil {
				slog.InfoContext(ctx, "Decryption failed (auth tag mismatch or tampered data)")
				return nil, errors.New("Decryption failed (auth tag mismatch or tampered data), check if encryption is embedding IV in the ciphertext?")
			}

			plaintext = plain
		}

		case "cbc": {

			slog.InfoContext(ctx, "Handling CBC mode of decryption")

			blockSize := block.BlockSize()

			if req.EnableHMAC {

				if len(data) < 32 {
					slog.InfoContext(ctx, "Missing HMAC tag")
					return nil, errors.New("Missing HMAC tag")
				}

				receivedTag := data[len(data)-32:]
				payload := data[:len(data)-32]

				macKey, err := s.Utils.DecodeByType(req.HMACKey, req.HMACKeyType)
				if err != nil {
					slog.InfoContext(ctx, "Exception in DecodeByType HMACKey", "error", err)
					return nil, err
				}

				// Reconstruct MAC input exactly as encryption did:
				var macInput []byte

				if req.IV != "" {
					// External IV case
					ivBytes, err := s.Utils.DecodeByType(req.IV, req.IVType)
					if err != nil {
						slog.InfoContext(ctx, "Exception in DecodeByType IV", "error", err)
						return nil, err
					}

					if len(ivBytes) != blockSize {
						slog.InfoContext(ctx, "Invalid IV length for CBC")
						return nil, errors.New("Invalid IV length for CBC")
					}

					macInput = make([]byte, 0, len(ivBytes)+len(payload))
					macInput = append(macInput, ivBytes...)
					macInput = append(macInput, payload...)

				} else {
					macInput = payload
				}

				expectedTag := s.Utils.ComputeHMAC(macInput, macKey)

				if !hmac.Equal(receivedTag, expectedTag) {
					slog.InfoContext(ctx, "Invalid HMAC - tampered ciphertext or missing IV")
					return nil, errors.New("Invalid HMAC - tampered ciphertext or missing IV")
				}

				data = payload
				slog.InfoContext(ctx, "Request has hmacKey", "payload", payload)
			}

			var iv []byte
			var ciphertext []byte

			if req.IV != "" {

				iv, err = s.Utils.DecodeByType(req.IV, req.IVType)
				if err != nil {
					slog.InfoContext(ctx, "Exception in DecodeByType IV", "error", err)
					return nil, err
				}

				if len(iv) != blockSize {
					slog.InfoContext(ctx, "Invalid IV length for CBC")
					return nil, errors.New("Invalid IV length for CBC")
				}

				ciphertext = data

			} else {

				if len(data) < blockSize {
					slog.InfoContext(ctx, "Ciphertext too short")
					return nil, errors.New("Ciphertext too short")
				}

				iv = data[:blockSize]
				ciphertext = data[blockSize:]
			}

			if len(ciphertext)%blockSize != 0 {
				slog.InfoContext(ctx, "Invalid ciphertext block size")
				return nil, errors.New("Invalid ciphertext block size")
			}

			mode := cipher.NewCBCDecrypter(block, iv)
			plain := make([]byte, len(ciphertext))
			mode.CryptBlocks(plain, ciphertext)

			paddingMode := strings.ToLower(req.Padding)

			slog.InfoContext(ctx, "", "mode", mode, "plain", plain, "paddingMode", paddingMode)

			switch paddingMode {

				case "", "pkcs5": {
					plain, err = s.Utils.Pkcs5Unpad(plain)
					if err != nil {
						slog.InfoContext(ctx, "Exception in Pkcs5Unpad", "error", err)
						return nil, err
					}
				}

				case "none": {}

				default: {
					slog.InfoContext(ctx, "Unsupported padding type")
					return nil, errors.New("Unsupported padding type (use pkcs5 or none)")
				}
			}

			plaintext = plain
		}

		default: {
			slog.InfoContext(ctx, "Unsupported mode")
			return nil, errors.New("Unsupported mode (gcm | cbc)")
		}
	}

	slog.InfoContext(ctx, "Cipher text decrypted, encoding to required output format", "plaintext", plaintext)

	var output string

	switch strings.ToLower(req.OutputFormat) {
		case "plain": {
			output = string(plaintext)
		}
		case "base64": {
			output = base64.StdEncoding.EncodeToString(plaintext)
		}
		case "base64url": {
			output = base64.RawURLEncoding.EncodeToString(plaintext)
		}
		default: {
			slog.InfoContext(ctx, "Output format not supported")
			return nil, errors.New("Output format not supported, use 'plain' or 'base64' or 'base64url'")
		}
	}

	slog.InfoContext(ctx, "returning from DecryptAES service method", "output", output)

	return &models.DecryptResponse{
		Plaintext: output,
	}, nil
}

func (s *UtilityService) AESKeyHmacPair(ctx context.Context, req models.AESKeyHmacPairRequest) (*models.AESKeyHmacPairResponse, error) {
	slog.InfoContext(ctx, "Inside AESKeyHmacPair service method")

	if req.Secret == "" {
		slog.InfoContext(ctx, "Secret is required")
		return nil, errors.New("Secret is required")
	}

	salt := []byte("almonds-crypto-salt")
	if req.Salt != "" {
		salt = []byte(req.Salt)
	}

	aesKeyBytes := 32
	hmacKeyBytes := 32

	if req.AesKeySizeInBytes > 0 {
		aesKeyBytes = req.AesKeySizeInBytes
		if aesKeyBytes != 16 && aesKeyBytes != 24 && aesKeyBytes != 32 {
			slog.InfoContext(ctx, "AES key must be 16, 24, or 32 bytes")
			return nil, errors.New("AES key must be 16, 24, or 32 bytes")
		}
	}

	if req.HmacKeySizeInBytes > 0 {
		hmacKeyBytes = req.HmacKeySizeInBytes
	}

	outputFormat := strings.ToLower(req.OutputFormat)
	if outputFormat == "" {
		outputFormat = "hex"
	}

	infoAES := []byte("aes-key")
	infoHMAC := []byte("hmac-key")

	hkdfAES := hkdf.New(crypto.SHA256.New, []byte(req.Secret), salt, infoAES)
	aesKey := make([]byte, aesKeyBytes)
	if _, err := io.ReadFull(hkdfAES, aesKey); err != nil {
		return nil, err
	}

	hkdfHMAC := hkdf.New(crypto.SHA256.New, []byte(req.Secret), salt, infoHMAC)
	hmacKey := make([]byte, hmacKeyBytes)
	if _, err := io.ReadFull(hkdfHMAC, hmacKey); err != nil {
		return nil, err
	}

	var encodedAES, encodedHMAC string

	switch outputFormat {
		case "hex": {
			encodedAES = hex.EncodeToString(aesKey)
			encodedHMAC = hex.EncodeToString(hmacKey)
		}

		case "base64": {
			encodedAES = base64.StdEncoding.EncodeToString(aesKey)
			encodedHMAC = base64.StdEncoding.EncodeToString(hmacKey)
		}

		case "base64url": {
			encodedAES = base64.RawURLEncoding.EncodeToString(aesKey)
			encodedHMAC = base64.RawURLEncoding.EncodeToString(hmacKey)
		}

		default: {
			slog.InfoContext(ctx, "Unsupported outputFormat")
			return nil, errors.New("Unsupported outputFormat: use hex, base64, or base64url")
		}
	}

	slog.InfoContext(ctx, "returning from AESKeyHmacPair service method", "encodedAES", encodedAES, "encodedHMAC", encodedHMAC)

	return &models.AESKeyHmacPairResponse{
		AesKey:  encodedAES,
		HmacKey: encodedHMAC,
	}, nil
}


func (s *UtilityService) GenerateBasicAuthPair(ctx context.Context, usernameLen, passwordLen int) (*models.BasicAuthResponse, error) {
	slog.InfoContext(ctx, "Inside GenerateBasicAuthPair service method")

	userSet := utils.USERNAME_SET
	passSet := utils.PASSWORD_SET

	user, err := s.Utils.RandomStringFromCharset(usernameLen, userSet)
	if err != nil {
		return nil, err
	}

	pass, err := s.Utils.RandomStringFromCharset(passwordLen, passSet)
	if err != nil {
		return nil, err
	}

	slog.InfoContext(ctx, "returning from GenerateBasicAuthPair service method", "user", user, "pass", pass)

	return &models.BasicAuthResponse{
		Username: user,
		Password: pass,
	}, nil
}


func (s *UtilityService) GenerateRandom(ctx context.Context, length int, randtype, characterset string) (res *models.RandomStringResponse, err error) {
	slog.InfoContext(ctx, "Inside GenerateRandom service method")
	
	var randomString string

	if characterset == "" {
		switch randtype {
			case "url-safe": {
				randomString, err = s.Utils.GenerateRandomURLSafe(length)
			}
			case "base64": {
				randomString, err = s.Utils.GenerateRandomBase64(length)
			}
			case "hex": {
				randomString, err = s.Utils.GenerateRandomHex(length)
			}
		}

	} else {
		if length == 0 {
			length =  utf8.RuneCountInString(characterset)
		}
		randomString, err = s.Utils.RandomStringFromCharset(length, characterset)
	}

	slog.InfoContext(ctx, "returning from GenerateRandom service method", "randomString", randomString)

	return &models.RandomStringResponse{
		Value: randomString,
	}, err
}
