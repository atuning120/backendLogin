package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type User struct {
	ID           primitive.ObjectID `bson:"_id,omitempty"`
	Email        string             `bson:"email"`
	Password     string             `bson:"password"`     // hashed
	CurrentToken string             `bson:"currentToken"` // último token JWT válido
	CreatedAt    primitive.DateTime `bson:"createdAt"`
	UpdatedAt    primitive.DateTime `bson:"updatedAt"`
}
