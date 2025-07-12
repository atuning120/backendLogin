package utils

import (
	"context"
	"my-backend/db"
	"my-backend/models"
	"os"
	"time"

	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func GenerateJWT(userID string) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// AuthMiddleware protege rutas y pone user_id en contexto
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token faltante o inválido"})
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		secret := os.Getenv("JWT_SECRET")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["user_id"] == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
			return
		}

		userIDStr := claims["user_id"].(string)
		userID, err := primitive.ObjectIDFromHex(userIDStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token inválido"})
			return
		}

		// Verificar que el token sea el último válido para este usuario
		var user models.User
		err = db.MongoClient.Database("db").Collection("users").
			FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Usuario no encontrado"})
			return
		}

		// Comparar el token actual con el almacenado en la base de datos
		if user.CurrentToken != tokenString {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expirado o invalidado por nueva sesión"})
			return
		}

		c.Set("user_id", userIDStr)
		c.Next()
	}
}

// InvalidateUserToken invalida el token actual de un usuario específico
func InvalidateUserToken(userID primitive.ObjectID) error {
	_, err := db.MongoClient.Database("db").Collection("users").UpdateOne(context.TODO(),
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{
			"currentToken": "",
			"updatedAt":    primitive.NewDateTimeFromTime(time.Now()),
		}},
	)
	return err
}
