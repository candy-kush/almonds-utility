package models

import "encoding/json"

type PDFRequest struct {
	Filename 	string 			`json:"filename"`
	Input      	*TicketRequest 	`json:"input"`
}

type TicketRequest struct {
	EventName      string    	`json:"eventName"`
	TotalPerson    int       	`json:"totalPerson"`
	Location       string    	`json:"location"`
	OrderDate      string    	`json:"orderDate"`
	EventDate      string    	`json:"eventDate"`
	Amount         int       	`json:"amount"`
	BookingID      string    	`json:"bookingId"`
	EventStartTime string    	`json:"eventStartTime"`
	EventEndTime   string    	`json:"eventEndTime"`
	QRCodes        []TicketQR 	`json:"qrCodes"`
}

type TicketQR struct {
	QRCode    string `json:"qrCode"`
	TicketFor string `json:"ticketFor"`
}

type QRRequest struct {
	ExportType 		string 		`json:"exportType"`
	ImageExtension 	string 		`json:"imageExtension"`
	Content 		string 		`json:"content"`
	Size 			int    		`json:"size,omitempty"`
}

type KeyIVResponse struct {
	Key  string `json:"key"`
	IV   string `json:"iv"`
}

type UUIDResponse struct {
	UUID string `json:"uuid"`
}

type PasswordRequest struct {
	Length       int  `json:"length"`
	SmallChars   bool `json:"smallChars"`
	BigChars     bool `json:"bigChars"`
	Numbers      bool `json:"numbers"`
	SpecialChars bool `json:"specialChars"`
}

type PasswordResponse struct {
	Password string  `json:"password"`
	Strength float64 `json:"strength"`
}

type HashRequest struct {
	Data   			json.RawMessage `json:"data"`
	Secret 			string 			`json:"secret"`
	Algo   			string 			`json:"algo"`
	OutputFormat 	string 			`json:"outputFormat"`
}

type HashResponse struct {
	Hash 		string `json:"hash"`
	Algorithm 	string `json:"algo"`
}

type CollisionProbabilityRequest struct {
	CharsetSize 	int 	`json:"charsetSize"`
	Length		 	int 	`json:"length"`
	Count   		int 	`json:"count"`
	Characterset   	string 	`json:"characterset"`
}

type CollisionResponse struct {
	Probability float64 `json:"probability"`
}

type EntropyRequest struct {
	Charset 		string 	`json:"characterset"`
	CharsetSize 	int 	`json:"charsetSize"`
	Length 			int 	`json:"length"`
}

type EntropyResponse struct {
	Entropy float64 `json:"entropy"`
}

type EncryptRequest struct {
    Plaintext     json.RawMessage `json:"plaintext"`

    Mode          string `json:"mode"`

    SecretKey     string `json:"secretKey"`
    SecretKeyType string `json:"secretKeyType"`

    IV            string `json:"iv,omitempty"`
    IVType        string `json:"ivType,omitempty"`

    Padding       string `json:"padding,omitempty"`

    EnableHMAC    bool   `json:"enableHmac,omitempty"`
    HMACKey       string `json:"hmacKey,omitempty"`
    HMACKeyType   string `json:"hmacKeyType,omitempty"`

    OutputFormat  string `json:"outputFormat"`
}

type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

type DecryptRequest struct {
    Ciphertext     string `json:"ciphertext"`
    InputFormat    string `json:"inputFormat"`

    Mode           string `json:"mode"`

    SecretKey      string `json:"secretKey"`
    SecretKeyType  string `json:"secretKeyType"`

	IV             string `json:"iv,omitempty"`
	IVType         string `json:"ivType,omitempty"`

    Padding        string `json:"padding,omitempty"`

    EnableHMAC     bool   `json:"enableHmac"`
    HMACKey        string `json:"hmacKey,omitempty"`
    HMACKeyType    string `json:"hmacKeyType,omitempty"`

	OutputFormat   string `json:"outputFormat"`
}

type DecryptResponse struct {
	Plaintext string `json:"plaintext"`
}

type AESKeyHmacPairRequest struct {
	Secret 				string 	`json:"secret,omitempty"`
	AesKeySizeInBytes 	int 	`json:"aesKeyBytes,omitempty"`
	HmacKeySizeInBytes 	int 	`json:"hmacKeyBytes,omitempty"`
	Salt 				string 	`json:"salt,omitempty"`
	OutputFormat  		string 	`json:"outputFormat"`
}

type AESKeyHmacPairResponse struct {
	AesKey 	string `json:"aesKey"`
	HmacKey string `json:"hmacKey"`
}

type BasicAuthResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RandomStringRequest struct {
	Length  int    `json:"length"`
	Charset string `json:"charset"`
	Type 	string `json:"type"`
}

type RandomStringResponse struct {
	Value string `json:"value"`
}

type BaseResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type APIResponse[T any] struct {
	BaseResponse
	Data    T      `json:"data,omitempty"`
}

type ClientProfile struct {
	ProfileID    string `json:"profileId"`
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
}