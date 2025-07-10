package main

import (
	"log"
	"os"

	"my-backend/controllers"
	"my-backend/db"
	"my-backend/utils"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load()
	db.InitMongo()
	db.InitRedis()

	r := gin.Default()

	r.POST("/register", controllers.Register)                                                                // Registro de usuario
	r.POST("/login", controllers.Login)                                                                      // Login de usuario
	r.POST("/send-recovery-token", controllers.SendRecoveryToken)                                            // recuperacion de correo
	r.POST("/reset-password/:token", controllers.ResetPassword)                                              // Resetear contraseña con token
	r.POST("/change-email", utils.AuthMiddleware(), controllers.ChangeEmail)                                 // Cambiar correo electrónico
	r.POST("/change-email-confirm", utils.AuthMiddleware(), controllers.ChangeEmailConfirm)                  // Confirmar cambio de correo electrónico
	r.POST("/change-email-cancel", utils.AuthMiddleware(), controllers.ChangeEmailCancel)                    // Cancelar cambio de correo electrónico
	r.POST("/change-email-history", utils.AuthMiddleware(), controllers.ChangeEmailHistory)                  // Ver historial de cambios de correo electrónico
	r.POST("/change-email-history/:id", utils.AuthMiddleware(), controllers.ChangeEmailHistoryByID)          // Ver historial de cambios de correo electrónico por ID
	r.POST("/change-email-history/delete/:id", utils.AuthMiddleware(), controllers.DeleteChangeEmailHistory) // Eliminar un registro de cambio de correo electrónico
	r.POST("/change-password", utils.AuthMiddleware(), controllers.ChangePassword)
	r.GET("/me", utils.AuthMiddleware(), controllers.Me)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Fatal(r.Run(":" + port))
}
