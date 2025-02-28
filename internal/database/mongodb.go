package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Global variables for MongoDB connection and JWT secret
var (
	Client    *mongo.Client
	Coll      *mongo.Collection
	Ctx       context.Context
	JwtSecret = []byte("esTRADA151200") // JWT secret key (hardcoded for now)
)

// Connect establishes a connection to the MongoDB database
func Connect() {
	// Load environment variables from the .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Retrieve the MongoDB URI from environment variables
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		log.Fatal("Missing environment variable: MONGODB_URI")
	}

	// Create a context with a timeout of 10 seconds
	Ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	// Connect to MongoDB using the provided URI
	Client, err = mongo.Connect(Ctx, options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}

	// Ping the MongoDB server to verify the connection
	err = Client.Ping(Ctx, nil)
	if err != nil {
		log.Fatal("Error connecting to MongoDB:", err)
	}
	fmt.Println("Successfully connected to MongoDB!")

	// Define the database and collection names
	dbName := "login"
	collectionName := "users"

	// Get a handle to the "users" collection in the "login" database
	Coll = Client.Database(dbName).Collection(collectionName)
}
