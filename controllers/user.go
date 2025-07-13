package controllers

import (
	"context"
	"fmt"
	"my-backend/db"
	"my-backend/models"
	"my-backend/utils"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
)

func GetUserIDFromContext(c *gin.Context) (primitive.ObjectID, error) {
	userIDStr, _ := c.Get("user_id")
	return primitive.ObjectIDFromHex(userIDStr.(string))
}

// GetConfirmationTokenFromHeader extrae el token de confirmación del header Authorization
func GetConfirmationTokenFromHeader(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("token de confirmación requerido en el header Authorization")
	}

	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		return "", fmt.Errorf("formato de token inválido. Use: Bearer <token>")
	}

	token := authHeader[len(bearerPrefix):]
	if token == "" {
		return "", fmt.Errorf("token de confirmación vacío")
	}

	return token, nil
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

	// Verifica si ya hizo un cambio de correo CONFIRMADO en los últimos 30 días
	now := time.Now()
	thirtyDaysAgo := now.Add(-30 * 24 * time.Hour)
	filter := bson.M{
		"user_id":    userID,
		"confirmed":  true, // Solo contar cambios confirmados
		"changed_at": bson.M{"$gt": primitive.NewDateTimeFromTime(thirtyDaysAgo)},
	}

	fmt.Printf("🔍 Verificando restricción de 30 días:\n")
	fmt.Printf("   Usuario ID: %s\n", userID.Hex())
	fmt.Printf("   Fecha actual: %s\n", now.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Fecha límite (30 días atrás): %s\n", thirtyDaysAgo.Format("2006-01-02 15:04:05"))

	count, err := db.MongoClient.Database("db").Collection("email_history").CountDocuments(context.TODO(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error interno"})
		return
	}

	fmt.Printf("   Cambios confirmados en los últimos 30 días: %d\n", count)

	if count > 0 {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Ya confirmaste un cambio de email en los últimos 30 días.",
			"info": fmt.Sprintf("Fecha actual: %s. Debes esperar hasta: %s",
				now.Format("2006-01-02 15:04:05"),
				thirtyDaysAgo.Add(30*24*time.Hour).Format("2006-01-02 15:04:05")),
		})
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

	// INVALIDAR todas las solicitudes de cambio de email pendientes anteriores para este usuario
	_, err = db.MongoClient.Database("db").Collection("email_history").UpdateMany(context.TODO(),
		bson.M{
			"user_id":   userID,
			"confirmed": false,
			"canceled":  false,
		},
		bson.M{"$set": bson.M{"canceled": true}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error invalidando solicitudes anteriores"})
		return
	}

	// Guardar solicitud de cambio en email_history (SIN cambiar el email todavía)
	confirmationToken := uuid.NewString() // Generar token de confirmación
	history := models.EmailHistory{
		UserID:    userID,
		OldEmail:  user.Email,
		NewEmail:  input.NewEmail,
		Token:     confirmationToken,
		Confirmed: false,
		Canceled:  false,
		ChangedAt: primitive.NewDateTimeFromTime(now),
		ExpiresAt: primitive.NewDateTimeFromTime(now.Add(30 * 24 * time.Hour)), //expira en 30 dias
	}
	_, err = db.MongoClient.Database("db").Collection("email_history").InsertOne(context.TODO(), history)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo guardar la solicitud de cambio"})
		return
	}

	// NO cambiamos el email todavía, solo guardamos la solicitud
	c.JSON(http.StatusOK, gin.H{
		"message":            "Solicitud de cambio de email creada. Tienes 1 minuto para confirmar.",
		"confirmation_token": confirmationToken,
		"expires_in":         "1 minuto",
		"info":               "El email NO se ha cambiado todavía. Si no confirmas en 1 minuto, la solicitud expirará automáticamente.",
	})
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

	// Generar nuevo token
	token, err := utils.GenerateJWT(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generando token"})
		return
	}

	// Actualizar el token actual en la base de datos (esto invalida tokens anteriores)
	_, err = db.MongoClient.Database("db").Collection("users").UpdateOne(context.TODO(),
		bson.M{"_id": user.ID},
		bson.M{"$set": bson.M{
			"currentToken": token,
			"updatedAt":    primitive.NewDateTimeFromTime(time.Now()),
		}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error actualizando sesión"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// ChangeEmailConfirm confirma el cambio de correo electrónico
func ChangeEmailConfirm(c *gin.Context) {
	// Obtener token de confirmación del header Authorization
	confirmationToken, err := GetConfirmationTokenFromHeader(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Buscar la solicitud de cambio pendiente usando el token de confirmación
	var emailHistory models.EmailHistory
	filter := bson.M{
		"token":      confirmationToken,
		"confirmed":  false,
		"canceled":   false,
		"expires_at": bson.M{"$gt": primitive.NewDateTimeFromTime(time.Now())},
	}

	err = db.MongoClient.Database("db").Collection("email_history").
		FindOne(context.TODO(), filter).Decode(&emailHistory)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token no encontrado, ya usado o expirado"})
		return
	}

	userID := emailHistory.UserID

	// VERIFICAR que este sea el último token de confirmación válido para este usuario
	// Buscamos si existe algún registro más reciente para este usuario
	var newerRequest models.EmailHistory
	newerFilter := bson.M{
		"user_id":    userID,
		"confirmed":  false,
		"canceled":   false,
		"changed_at": bson.M{"$gt": emailHistory.ChangedAt}, // Más reciente que el actual
	}

	err = db.MongoClient.Database("db").Collection("email_history").
		FindOne(context.TODO(), newerFilter).Decode(&newerRequest)
	if err == nil {
		// Existe un token más reciente, invalidar este
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalidado por una solicitud más reciente"})
		return
	}

	// Verificar que el nuevo email no esté en uso por otro usuario
	var existingUser models.User
	err = db.MongoClient.Database("db").Collection("users").
		FindOne(context.TODO(), bson.M{
			"email": emailHistory.NewEmail,
			"_id":   bson.M{"$ne": userID}, // Excluir el usuario actual
		}).Decode(&existingUser)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "El email ya está en uso por otro usuario"})
		return
	}

	// AHORA SÍ cambiamos el email del usuario
	_, err = db.MongoClient.Database("db").Collection("users").UpdateOne(context.TODO(),
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{
			"email":     emailHistory.NewEmail,
			"updatedAt": primitive.NewDateTimeFromTime(time.Now()),
		}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo actualizar el email"})
		return
	}

	// Marcar como confirmado en el historial con la fecha actual
	_, err = db.MongoClient.Database("db").Collection("email_history").UpdateOne(context.TODO(),
		bson.M{"_id": emailHistory.ID},
		bson.M{"$set": bson.M{
			"confirmed":  true,
			"changed_at": primitive.NewDateTimeFromTime(time.Now()), // Actualizar a la fecha de confirmación
		}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo actualizar el historial"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Email cambiado exitosamente",
		"old_email": emailHistory.OldEmail,
		"new_email": emailHistory.NewEmail,
	})
}

// ChangeEmailCancel cancela el cambio de correo electrónico
func ChangeEmailCancel(c *gin.Context) {
	// Obtener token de confirmación del header Authorization
	confirmationToken, err := GetConfirmationTokenFromHeader(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Buscar la solicitud de cambio pendiente usando el token de confirmación
	var emailHistory models.EmailHistory
	filter := bson.M{
		"token":     confirmationToken,
		"confirmed": false,
		"canceled":  false,
	}

	err = db.MongoClient.Database("db").Collection("email_history").
		FindOne(context.TODO(), filter).Decode(&emailHistory)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Token no encontrado o ya procesado"})
		return
	}

	userID := emailHistory.UserID

	// VERIFICAR que este sea el último token de confirmación válido para este usuario
	// Buscamos si existe algún registro más reciente para este usuario
	var newerRequest models.EmailHistory
	newerFilter := bson.M{
		"user_id":    userID,
		"confirmed":  false,
		"canceled":   false,
		"changed_at": bson.M{"$gt": emailHistory.ChangedAt}, // Más reciente que el actual
	}

	err = db.MongoClient.Database("db").Collection("email_history").
		FindOne(context.TODO(), newerFilter).Decode(&newerRequest)
	if err == nil {
		// Existe un token más reciente, invalidar este
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token invalidado por una solicitud más reciente"})
		return
	}

	// Marcar como cancelado
	_, err = db.MongoClient.Database("db").Collection("email_history").UpdateOne(context.TODO(),
		bson.M{"_id": emailHistory.ID},
		bson.M{"$set": bson.M{"canceled": true}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No se pudo cancelar la solicitud"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Solicitud de cambio de email cancelada",
		"old_email":      emailHistory.OldEmail,
		"canceled_email": emailHistory.NewEmail,
	})
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

// CleanExpiredEmailTokens limpia tokens de email expirados que no fueron confirmados ni cancelados
func CleanExpiredEmailTokens() {
	filter := bson.M{
		"confirmed":  false,
		"canceled":   false,
		"expires_at": bson.M{"$lt": primitive.NewDateTimeFromTime(time.Now())},
	}

	// Opcional: Log de cuántos se eliminaron
	result, err := db.MongoClient.Database("db").Collection("email_history").DeleteMany(context.TODO(), filter)
	if err == nil && result.DeletedCount > 0 {
		// En un log real usarías un logger apropiado
		fmt.Printf("Limpiados %d tokens de email expirados\n", result.DeletedCount)
	}
}

// Logout invalida el token actual del usuario
func Logout(c *gin.Context) {
	userID, err := GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No autorizado"})
		return
	}

	// Limpiar el token actual para invalidar la sesión
	_, err = db.MongoClient.Database("db").Collection("users").UpdateOne(context.TODO(),
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{
			"currentToken": "",
			"updatedAt":    primitive.NewDateTimeFromTime(time.Now()),
		}},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error cerrando sesión"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Sesión cerrada exitosamente"})
}
