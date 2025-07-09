package main

import (
	"log"
	"os"

	"my-backend/controllers"
	"my-backend/db"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	db.InitMongo()
	db.InitRedis()

	r := gin.Default()

	r.POST("/register", controllers.Register)
	r.POST("/login", controllers.Login)
	r.POST("/send-recovery-token", controllers.SendRecoveryToken)
	r.POST("/reset-password/:token", controllers.ResetPassword)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(r.Run(":" + port))
}
