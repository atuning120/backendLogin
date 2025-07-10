package controllers

import (
	"my-backend/db"
	"my-backend/models"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// Enviar token de recuperación
func SendRecoveryToken(c *gin.Context) {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email inválido"})
		return
	}

	// Validar formato de email básico
	if input.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email requerido"})
		return
	}

	// Buscar usuario
	var user models.User
	err := db.MongoClient.Database("db").Collection("users").
		FindOne(c, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		// Por seguridad, no revelar si el email existe o no
		c.JSON(http.StatusOK, gin.H{"message": "Si el email existe, se enviará un token de recuperación"})
		return
	}

	token := uuid.NewString()
	// Guardar token con TTL de 1 hora para mayor seguridad
	db.RedisClient.Set(db.Ctx, "recovery_token:"+token, user.ID.Hex(), 1*time.Hour)

	// Aquí deberías enviar el correo real con el token (utils.SendEmail)
	// Por ahora, devolvemos el token solo para desarrollo
	c.JSON(http.StatusOK, gin.H{
		"message": "Token de recuperación enviado",
		"token":   token, // Remover en producción
		"info":    "En producción, este token se enviará por email y no se mostrará en la respuesta",
	})
}

// Resetear contraseña con token
func ResetPassword(c *gin.Context) {
	// Obtener token del header Authorization
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token de recuperación requerido"})
		return
	}

	// Verificar formato "Bearer <token>"
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Formato de token inválido. Use: Bearer <token>"})
		return
	}

	token := authHeader[len(bearerPrefix):]
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token de recuperación vacío"})
		return
	}

	var input struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password inválido"})
		return
	}

	// Validar que la contraseña no esté vacía
	if input.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "La contraseña no puede estar vacía"})
		return
	}

	userID, err := db.RedisClient.Get(db.Ctx, "recovery_token:"+token).Result()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token de recuperación inválido o expirado"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)

	// Actualizar contraseña
	objID, _ := primitive.ObjectIDFromHex(userID)
	_, err = db.MongoClient.Database("db").Collection("users").
		UpdateOne(c, bson.M{"_id": objID}, bson.M{
			"$set": bson.M{
				"password":  string(hash),
				"updatedAt": primitive.NewDateTimeFromTime(time.Now()),
			},
		})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al actualizar la contraseña"})
		return
	}

	// Eliminar el token usado para evitar reutilización
	db.RedisClient.Del(db.Ctx, "recovery_token:"+token)

	c.JSON(http.StatusOK, gin.H{"message": "Contraseña actualizada correctamente"})
}
