package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// User represents a user with username, password, and role.
type User struct {
	Username string
	Password string
	Role     string
}

// DeviceInfo represents device information.
type DeviceInfo struct {
	DeviceNumber int    `gorm:"column:device_number;primaryKey"`
	Address      string `gorm:"column:address"`
}

// Policy represents a policy rule.
type Policy struct {
	PType string `gorm:"column:p"`
	V0    string `gorm:"column:v0"`
	V1    string `gorm:"column:v1"`
	V2    string `gorm:"column:v2"`
}

// Claims represents the JWT claims, including the user's role.
type Claims struct {
	Role string `json:"role"`
	jwt.StandardClaims
}

// TableName sets the table name for the User model.
func (d *User) TableName() string {
	return "userinfo"
}

// TableName sets the table name for the DeviceInfo model.
func (d *DeviceInfo) TableName() string {
	return "deviceinfo"
}

// TableName sets the table name for the Policy model.
func (p *Policy) TableName() string {
	return "policy"
}

// initDB initializes the database connection.
func initDB() (*gorm.DB, error) {
	// Replace these connection parameters with your PostgreSQL configuration.
	dsn := "user=postgres password=12345 dbname=hari host=localhost port=5432 sslmode=disable"

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto Migrate the User, DeviceInfo, and Policy models to create the tables.
	db.AutoMigrate(&User{}, &DeviceInfo{}, &Policy{})

	return db, nil
}

// createJWTToken creates a JWT token with user claims.
func createJWTToken(username, role string) string {
	claims := Claims{
		Role: role,
		StandardClaims: jwt.StandardClaims{
			Subject: username,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("your-secret-key"))
	return tokenString
}

// extractTokenFromRequest extracts a JWT token from the request.
func extractTokenFromRequest(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if token != "" {
		return strings.TrimPrefix(token, "Bearer ")
	}
	return ""
}

// validateJWTToken validates a JWT token and returns the claims.
func validateJWTToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	if err != nil {
		fmt.Println("JWT Parse Error:", err)
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		fmt.Println("JWT Claims:", claims)
		return claims, nil
	}

	fmt.Println("Invalid token")
	return nil, fmt.Errorf("error")
}

// authenticateUser authenticates the user against the database and Casbin policy.
func authenticateUser(d *gorm.DB, e *casbin.Enforcer, username, password, role string) bool {
	var user User
	result := d.Where(&User{Username: username, Password: password, Role: role}).First(&user)
	if result.Error != nil {
		fmt.Printf("Database Error: %v\n", result.Error)
		return false
	}

	fmt.Printf("User found: %s (Role: %s) (pass: %s)\n", user.Username, user.Role, user.Password)

	// Check if the retrieved user's role matches the provided role.
	if user.Role != role {
		fmt.Println("Role mismatch:", user.Role, "!= expected role:", role)
		return false
	}

	// Check if the user's role matches the Casbin policy.
	ok, err := e.Enforce(user.Role, "/", "GET")
	if err != nil {
		fmt.Println("Casbin Policy Check Error:", err)
		return false
	}

	fmt.Println("Casbin Policy Check Result:", ok)

	return ok
}

// dbClose closes the database connection.
func dbClose(db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		fmt.Println("Failed to get underlying database connection:", err)
		return
	}
	if err := sqlDB.Close(); err != nil {
		fmt.Println("Failed to close database connection:", err)
	}
}

func main() {
	// Initialize the database.
	db, err := initDB()
	if err != nil {
		panic("Failed to connect to the database")
	}
	defer dbClose(db)

	// Create a Casbin adapter using the PostgreSQL database for the "policy" table.
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		panic("Failed to create Casbin adapter")
	}

	// Initialize the Casbin enforcer with the adapter and model.
	e, err := casbin.NewEnforcer("model.conf", adapter)

	if err != nil {
		panic("Failed to initialize Casbin")
	}

	// Load the policy rules and print them for debugging.
	if err := e.LoadPolicy(); err != nil {
		panic("Failed to load policy rules: " + err.Error())
	}
	fmt.Println("Policy rules loaded successfully")

	r := mux.NewRouter()

	// Serve the login form.
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
	})

	// Login handler
	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse the form data from the request.
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		role := r.FormValue("role")

		// Debugging: Print received data.
		fmt.Printf("Received username: %s\n", username)
		fmt.Printf("Received password: %s\n", password)
		fmt.Printf("Received role: %s\n", role)

		// Authenticate the user.
		// Inside the login handler
		if authenticateUser(db, e, username, password, role) {
			fmt.Println("Authentication successful")

			// Create a JWT token with user claims.
			token := createJWTToken(username, role)
			fmt.Println("JWT Token:", token) // Print the token for debugging

			// Send the token in the response.
			w.Header().Set("Authorization", "Bearer "+token)

			// Redirect to the dashboard upon successful login.
			http.Redirect(w, r, "/dashboard?token="+token, http.StatusSeeOther)

		} else {
			// Return an error message for failed login.
			http.Error(w, "Login failed: Invalid credentials.", http.StatusUnauthorized)
			return
		}

	})

	// Dashboard handler
	r.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		// Extract and validate the JWT token from the query parameters.
		tokenString := r.URL.Query().Get("token")

		if tokenString == "" {
			log.Println("No JWT token found in the request")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log.Println("JWT Token:", tokenString) // Print the token for debugging

		claims, err := validateJWTToken(tokenString)
		if err != nil {
			log.Println("JWT Token Validation Error:", err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		log.Printf("Role: %s\n", claims.Role)
		var devices []DeviceInfo
		if claims.Role == "admin" {
			// Admin has access to all data.
			result := db.Find(&devices)
			if result.Error != nil {
				log.Println("Database Error:", result.Error)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		} else {
			// Non-admin users have access based on their role in the address column.
			result := db.Where("address = ?", claims.Role).Find(&devices)
			if result.Error != nil {
				log.Println("Database Error:", result.Error)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		// Render a dashboard template to display the records.
		tmpl, err := template.ParseFiles("templates/dashboard.html")
		if err != nil {
			log.Println("Template Error:", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, devices)
	})

	// Start the web server.
	fmt.Println("Server is running on :8000")
	http.ListenAndServe(":8000", r)
}
