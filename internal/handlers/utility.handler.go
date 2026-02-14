package handlers

import (
	"log/slog"
	"net/http"
	"strconv"

	"almonds-utility/internal/models"
	"almonds-utility/internal/service"

	"github.com/gin-gonic/gin"
)

type UtilityHandler struct {
	Service *service.UtilityService
}

func NewUtilityHandler(s *service.UtilityService) *UtilityHandler {
	return &UtilityHandler{Service: s}
}

func (h *UtilityHandler) GeneratePDF(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.PDFRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "GeneratePDF - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside GeneratePDF handler", "request", req)

	pdfBytes, filename, err := h.Service.GeneratePDF(ctx, req)
	
	if err != nil {
		slog.InfoContext(ctx, "GeneratePDF - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	c.Header("Content-Disposition", "attachment; filename=" + filename)
	c.Data(http.StatusOK, "application/pdf", pdfBytes)
}

func (h *UtilityHandler) GenerateQR(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.QRRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "GenerateQR - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside GenerateQR handler", "request", req)

	qrBytes, err := h.Service.GenerateQR(ctx, req)
	if err != nil {
		slog.InfoContext(ctx, "GenerateQR - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	slog.InfoContext(ctx, "GenerateQR - Success Response")
	imageType := "image/" + req.ImageExtension

	c.Data(http.StatusOK, imageType, qrBytes)
}

func (h *UtilityHandler) GenerateKeyIV(c *gin.Context) {
	ctx := c.Request.Context()
	slog.InfoContext(ctx, "Inside GenerateKeyIV handler", "request", 
		slog.Group("request",
        	"keyBytes", c.Query("keyBytes"),
        	"ivBytes", c.Query("ivBytes"),
        	"encoding", c.Query("encoding"),
	    ),
	)

	keyBytes, _ := strconv.Atoi(c.DefaultQuery("keyBytes", "32"))
	ivBytes, _ := strconv.Atoi(c.DefaultQuery("ivBytes", "16"))
	encoding := c.DefaultQuery("encoding", "hex")

	data, err := h.Service.GenerateKeyIVPair(ctx, keyBytes, ivBytes, encoding)
	if err != nil {
		slog.InfoContext(ctx, "GenerateKeyIV - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.KeyIVResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Key-IV pair generated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "GenerateKeyIV - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}

func (h *UtilityHandler) GenerateUUID(c *gin.Context) {
	ctx := c.Request.Context()
	slog.InfoContext(ctx, "Inside GenerateUUID handler", "request", 
		slog.Group("request",
        	"type", c.Query("type"),
        	"version", c.Query("version"),
	    ),
	)

	uuidType := c.DefaultQuery("type", "uuid")
	version := c.DefaultQuery("version", "v4")
	data, err := h.Service.GenerateUUID(ctx, uuidType, version)

	if err != nil {
		slog.InfoContext(ctx, "GenerateUUID - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.UUIDResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "UUID/ULID generated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "GenerateUUID - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}

func (h *UtilityHandler) GeneratePassword(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.PasswordRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "GeneratePassword - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside GeneratePassword handler", "request", req)

	data, err := h.Service.GeneratePassword(ctx, req)
	if err != nil {
		slog.InfoContext(ctx, "GeneratePassword - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.PasswordResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Strong and crypto-secure password generated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "GeneratePassword - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}


func (h *UtilityHandler) HashWithKey(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.HashRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "HashWithKey - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside HashWithKey handler", "request", req)

	data, err := h.Service.HashWithKey(ctx, req)
	if err != nil {
		slog.InfoContext(ctx, "HashWithKey - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.HashResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Hash value generated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "HashWithKey - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}

func (h *UtilityHandler) CollisionProbability(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.CollisionProbabilityRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "CollisionProbability - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside CollisionProbability handler", "request", req)

	characterset := req.Characterset
	length := req.Length
	charsetSize := req.CharsetSize
	count := req.Count

	data, err := h.Service.CollisionProbability(ctx, length, charsetSize, count, characterset)
	if err != nil {
		slog.InfoContext(ctx, "CollisionProbability - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.CollisionResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Collision probability calculated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "CollisionProbability - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}


func (h *UtilityHandler) CalculateEntropy(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.EntropyRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "CalculateEntropy - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside CalculateEntropy handler", "request", req)

	data, err := h.Service.CalculateEntropy(ctx, req.Length, req.CharsetSize, req.Charset)

	if err != nil {
		slog.InfoContext(ctx, "CalculateEntropy - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.EntropyResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Entropy calculated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "CalculateEntropy - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}


func (h *UtilityHandler) EncryptAESGCM(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.EncryptRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "EncryptAESGCM - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside EncryptAESGCM handler", "request", req)

	data, err := h.Service.EncryptAES(ctx, req)

	if err != nil {
		slog.InfoContext(ctx, "EncryptAESGCM - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.EncryptResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Plaintext encrypted securely",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "EncryptAESGCM - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}


func (h *UtilityHandler) DecryptAESGCM(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.DecryptRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "DecryptAESGCM - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside DecryptAESGCM handler", "request", req)

	data, err := h.Service.DecryptAES(ctx, req)
	
	if err != nil {
		slog.InfoContext(ctx, "DecryptAESGCM - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.DecryptResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Ciphertext decrypted successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "DecryptAESGCM - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}

func (h *UtilityHandler) AESKeyHmacPair(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.AESKeyHmacPairRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "AESKeyHmacPair - JSON Binding Failed",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request",
		})
		return
	}

	slog.InfoContext(ctx, "Inside AESKeyHmacPair handler", "request", req)

	data, err := h.Service.AESKeyHmacPair(ctx, req)
	
	if err != nil {
		slog.InfoContext(ctx, "AESKeyHmacPair - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.AESKeyHmacPairResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "AES-HMAC key pair generated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "AESKeyHmacPair - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}


func (h *UtilityHandler) GenerateBasicAuth(c *gin.Context) {
	ctx := c.Request.Context()
	slog.InfoContext(ctx, "Inside GenerateBasicAuth handler", "request", 
		slog.Group("request",
        	"userLen", c.Query("userLen"),
        	"passLen", c.Query("passLen"),
	    ),
	)

	userLen, _ := strconv.Atoi(c.DefaultQuery("userLen", "12"))
	passLen, _ := strconv.Atoi(c.DefaultQuery("passLen", "16"))

	data, err := h.Service.GenerateBasicAuthPair(ctx, userLen, passLen)

	if err != nil {
		slog.InfoContext(ctx, "GenerateBasicAuth - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.BasicAuthResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Secure basic auth pair generated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "GenerateBasicAuth - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}

func (h *UtilityHandler) GenerateRandom(c *gin.Context) {
	ctx := c.Request.Context()
	var req models.RandomStringRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.InfoContext(ctx, "GenerateRandom - JSON Binding Failed",
			"error", err,
		)
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: "Invalid Request Body",
		})
		return
	}
	
	slog.InfoContext(ctx, "Inside GenerateRandom handler", "request", req)

	data, err := h.Service.GenerateRandom(ctx, req.Length, req.Type, req.Charset)

	if err != nil {
		slog.InfoContext(ctx, "GenerateRandom - Service Error",
            "error", err,
        )
		c.JSON(http.StatusBadRequest, models.BaseResponse{
			Code:    400,
			Message: err.Error(),
		})
		return
	}

	response := models.APIResponse[models.RandomStringResponse]{
		BaseResponse: models.BaseResponse{
			Code:    200,
			Message: "Crypto secured randomized string generated successfully",
		},
		Data: *data,
	}

	slog.InfoContext(ctx, "GenerateRandom - Success Response",
        "response", response,
    )

	c.JSON(http.StatusOK, response)
}
