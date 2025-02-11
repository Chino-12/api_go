package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors" // Importar el paquete CORS
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Variables globales para la conexión a MongoDB
var client *mongo.Client
var coll *mongo.Collection

// Clave secreta para firmar tokens JWT (debería estar en un archivo .env)
var jwtSecret = []byte("esTRADA151200")

// Estructura para el usuario
type User struct {
	Email    string `json:"email" bson:"email"`
	Password string `json:"password" bson:"password"`
}

func main() {
	// Cargar el archivo .env que contiene las variables de entorno
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Obtener la URL de conexión desde las variables de entorno
	uri := os.Getenv("MONGODB_URI")
	if uri == "" {
		log.Fatal("Falta la variable de entorno MONGODB_URI")
	}

	// Crear un contexto con timeout de 10 segundos
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel() // Asegurarse de que se liberen los recursos

	// Intentar conectar a MongoDB
	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		panic(err)
	}

	// Verificar que la conexión fue exitosa
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Error al conectar a MongoDB:", err)
	}
	fmt.Println("¡Conexión exitosa a MongoDB!")

	// Asegurarse de cerrar la conexión al terminar
	defer func() {
		if err := client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()

	// Seleccionar la base de datos y la colección
	dbName := "login"
	collectionName := "users"
	coll = client.Database(dbName).Collection(collectionName)

	// Configurar el router para la API
	r := mux.NewRouter()

	// Definir las rutas de la API
	r.HandleFunc("/login", login).Methods("POST")       // Endpoint para login
	r.HandleFunc("/register", register).Methods("POST") // Endpoint para registro

	// Configurar CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:4200"}, // Permitir solicitudes desde Angular
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	// Aplicar el middleware CORS al router
	handler := c.Handler(r)

	// Iniciar el servidor HTTP en el puerto 8080
	fmt.Println("Servidor corriendo en http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// Función para manejar el login
func login(w http.ResponseWriter, r *http.Request) {
	var user User

	// Agregar headers CORS
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:4200")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	// Handle preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Decodificar el cuerpo de la solicitud
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Datos inválidos"})
		return
	}

	// Buscar el usuario en la base de datos
	var dbUser User
	err := coll.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&dbUser)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Credenciales incorrectas"})
		return
	}

	// Verificar la contraseña (en una aplicación real, usa bcrypt)
	if dbUser.Password != user.Password {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Credenciales incorrectas"})
		return
	}

	// Generar un token JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": dbUser.Email,
		"exp":   time.Now().Add(time.Hour * 24).Unix(), // Token expira en 24 horas
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error al generar el token"})
		return
	}

	// Devolver el token
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":   tokenString,
		"message": "Login exitoso",
	})
}

// Función para manejar el registro
func register(w http.ResponseWriter, r *http.Request) {
	var user User

	// Decodificar el cuerpo de la solicitud
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Datos inválidos"})
		return
	}

	// Insertar el usuario en la base de datos
	_, err := coll.InsertOne(context.TODO(), user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Error al registrar el usuario"})
		return
	}

	// Devolver una respuesta exitosa
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Usuario registrado"})
}
