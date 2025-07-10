package controllers

import (
	"context"
	"my-backend/db"
	"my-backend/models"
	"my-backend/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

func GetUserIDFromContext(c *gin.Context) (primitive.ObjectID, error) {
	userIDStr, _ := c.Get("user_id")
	return primitive.ObjectIDFromHex(userIDStr.(string))
}

// Cambiar correo, solo 1 vez cada 30 días
func ChangeEmail(c *gin.Context) {
	var input struct {
		NewEmail string `json:"new_email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email inválido"})
		return
	}
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	// Verifica si ya hizo un cambio de correo y si está vigente
	now := time.Now()
	filter := bson.M{
		"user_id":    userID,
		"expires_at": bson.M{"$gt": primitive.NewDateTimeFromTime(now)},
	}
	count, err := db.MongoClient.Database("db").Collection("email_history").CountDocuments(context.TODO(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error interno"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "Solo puedes cambiar tu correo una vez cada 30 días."})
		return
	}

	// Verificar si el nuevo email ya existe en otro usuario
	var existingUser models.User
	err = db.MongoClient.Database("db").Collection("users").
		FindOne(context.TODO(), bson.M{"email": input.NewEmail}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "El email ya está en uso"})
		return
	}

	// Buscar usuario actual
	var user models.User
	if err := db.MongoClient.Database("db").Collection("users").FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Usuario no encontrado"})
		return
	}

	// Guardar email antiguo en email_history
	history := models.EmailHistory{
		UserID:    userID,
		OldEmail:  user.Email,
		NewEmail:  input.NewEmail,
		Confirmed: false,
		Canceled:  false,
		ChangedAt: primitive.NewDateTimeFromTime(now),
		ExpiresAt: primitive.NewDateTimeFromTime(now.Add(30 * 24 * time.Hour)),
	}
	_, err = db.MongoClient.Database("db").Collection("email_history").InsertOne(context.TODO(), history)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo guardar el historial"})
		return
	}

	// Cambiar email en users
	_, err = db.MongoClient.Database("db").Collection("users").UpdateOne(context.TODO(),
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{
			"email":     input.NewEmail,
			"updatedAt": primitive.NewDateTimeFromTime(time.Now()),
		}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo actualizar el correo"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Correo actualizado correctamente"})
}

func ChangePassword(c *gin.Context) {
	var input struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos"})
		return
	}
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	// Obtener usuario actual
	var user models.User
	if err := db.MongoClient.Database("db").Collection("users").FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Usuario no encontrado"})
		return
	}

	// Verifica contraseña anterior
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.OldPassword)) != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Contraseña actual incorrecta"})
		return
	}
	// Actualiza nueva
	hash, _ := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	_, err = db.MongoClient.Database("db").Collection("users").UpdateOne(context.TODO(),
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{
			"password":  string(hash),
			"updatedAt": primitive.NewDateTimeFromTime(time.Now()),
		}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo cambiar la contraseña"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Contraseña cambiada"})
}

func Me(c *gin.Context) {
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	var user models.User
	err = db.MongoClient.Database("db").Collection("users").FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Usuario no encontrado"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":        user.ID.Hex(),
		"email":     user.Email,
		"createdAt": user.CreatedAt.Time(),
	})
}

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

	// Verificar si ya existe un usuario con este email
	var existingUser models.User
	err := db.MongoClient.Database("db").Collection("users").
		FindOne(context.TODO(), bson.M{"email": input.Email}).Decode(&existingUser)

	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "El usuario ya existe"})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	now := time.Now()
	user := models.User{
		Email:     input.Email,
		Password:  string(hash),
		CreatedAt: primitive.NewDateTimeFromTime(now),
		UpdatedAt: primitive.NewDateTimeFromTime(now),
	}

	_, err = db.MongoClient.Database("db").Collection("users").InsertOne(context.TODO(), user)
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
	err := db.MongoClient.Database("db").Collection("users").
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

// ChangeEmailConfirm confirma el cambio de correo electrónico
func ChangeEmailConfirm(c *gin.Context) {
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	var input struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token inválido"})
		return
	}

	// Verificar el token y actualizar el correo
	filter := bson.M{
		"user_id": userID,
		"token":   input.Token,
	}
	update := bson.M{"$set": bson.M{"confirmed": true}}
	result, err := db.MongoClient.Database("db").Collection("email_history").UpdateOne(context.TODO(), filter, update)
	if err != nil || result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token no encontrado o ya confirmado"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Correo electrónico confirmado"})
}

// ChangeEmailCancel cancela el cambio de correo electrónico
func ChangeEmailCancel(c *gin.Context) {
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	var input struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Token inválido"})
		return
	}

	// Verificar el token y cancelar el cambio
	filter := bson.M{
		"user_id": userID,
		"token":   input.Token,
	}
	update := bson.M{"$set": bson.M{"canceled": true}}
	result, err := db.MongoClient.Database("db").Collection("email_history").UpdateOne(context.TODO(), filter, update)
	if err != nil || result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token no encontrado o ya cancelado"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Cambio de correo electrónico cancelado"})
}

// ChangeEmailHistory obtiene el historial de cambios de correo electrónico
func ChangeEmailHistory(c *gin.Context) {
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	var emailHistory []models.EmailHistory
	cursor, err := db.MongoClient.Database("db").Collection("email_history").
		Find(context.TODO(), bson.M{"user_id": userID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al obtener historial"})
		return
	}
	defer cursor.Close(context.TODO())

	for cursor.Next(context.TODO()) {
		var record models.EmailHistory
		if err := cursor.Decode(&record); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al decodificar historial"})
			return
		}
		emailHistory = append(emailHistory, record)
	}

	c.JSON(http.StatusOK, emailHistory)
}

// ChangeEmailHistoryByID obtiene un registro específico del historial de cambios de correo electrónico
func ChangeEmailHistoryByID(c *gin.Context) {
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID inválido"})
		return
	}

	var record models.EmailHistory
	err = db.MongoClient.Database("db").Collection("email_history").
		FindOne(context.TODO(), bson.M{"_id": id, "user_id": userID}).Decode(&record)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Registro no encontrado"})
		return
	}

	c.JSON(http.StatusOK, record)
}

// DeleteChangeEmailHistory elimina un registro del historial de cambios de correo electrónico
func DeleteChangeEmailHistory(c *gin.Context) {
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	idStr := c.Param("id")
	id, err := primitive.ObjectIDFromHex(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID inválido"})
		return
	}

	result, err := db.MongoClient.Database("db").Collection("email_history").
		DeleteOne(context.TODO(), bson.M{"_id": id, "user_id": userID})
	if err != nil || result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Registro no encontrado o ya eliminado"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registro eliminado"})
}
