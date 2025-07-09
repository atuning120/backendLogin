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
	// Buscar usuario
	var user models.User
	err := db.MongoClient.Database("mi_base").Collection("users").
		FindOne(c, bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Usuario no encontrado"})
		return
	}

	token := uuid.NewString()
	db.RedisClient.Set(db.Ctx, "recovery_token:"+token, user.ID.Hex(), 24*time.Hour)
	// Aquí deberías enviar el correo real con el token (utils.SendEmail)
	c.JSON(http.StatusOK, gin.H{"message": "Token enviado (simulado)", "token": token})
}

// Resetear contraseña con token
func ResetPassword(c *gin.Context) {
	token := c.Param("token")
	var input struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password inválido"})
		return
	}
	userID, err := db.RedisClient.Get(db.Ctx, "recovery_token:"+token).Result()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token inválido"})
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	// Actualizar contraseña
	objID, _ := primitive.ObjectIDFromHex(userID)
	db.MongoClient.Database("mi_base").Collection("users").
		UpdateOne(c, bson.M{"_id": objID}, bson.M{"$set": bson.M{"password": string(hash)}})
	db.RedisClient.Del(db.Ctx, "recovery_token:"+token)
	c.JSON(http.StatusOK, gin.H{"message": "Contraseña actualizada"})
}
