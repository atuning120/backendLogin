package controllers

import (
	"context"
	"net/http"
	"time"

	"my-backend/db"
	"my-backend/models"
	"my-backend/utils"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

// Registro de usuario
func Register(c *gin.Context) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	user := models.User{
		Email:     input.Email,
		Password:  string(hash),
		CreatedAt: primitive.NewDateTimeFromTime(time.Now()),
	}

	_, err := db.MongoClient.Database("mi_base").Collection("users").InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creando usuario"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"message": "Usuario registrado"})
}

// Login de usuario (retorna token JWT)
func Login(c *gin.Context) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
		return
	}

	var user models.User
	err := db.MongoClient.Database("mi_base").Collection("users").
		FindOne(context.TODO(), bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciales incorrectas"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciales incorrectas"})
		return
	}

	token, _ := utils.GenerateJWT(user.ID.Hex())
	c.JSON(http.StatusOK, gin.H{"token": token})
}
