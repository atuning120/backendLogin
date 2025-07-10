package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type EmailHistory struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	UserID    primitive.ObjectID `bson:"user_id"`
	OldEmail  string             `bson:"old_email"`
	NewEmail  string             `bson:"new_email"`
	Token     string             `bson:"token,omitempty"`
	Confirmed bool               `bson:"confirmed"`
	Canceled  bool               `bson:"canceled"`
	ChangedAt primitive.DateTime `bson:"changed_at"`
	ExpiresAt primitive.DateTime `bson:"expires_at"` // TTL index
}
