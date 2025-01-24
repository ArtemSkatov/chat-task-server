package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"unique"`
	Password string
}

func main() {
	fmt.Println("🚀 Starting server...")

	// 1. Настройка SQLite через modernc.org/sqlite
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		fmt.Println("❌ Database error:", err)
		os.Exit(1)
	}

	// 2. Автомиграция
	if err := db.AutoMigrate(&User{}); err != nil {
		fmt.Println("❌ Migration failed:", err)
		os.Exit(1)
	}

	// 3. Настройка Gin
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"*"},
		AllowHeaders:     []string{"*"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// 4. Роутинг
	r.POST("/register", registerHandler(db))
	r.GET("/health", healthCheck)

	fmt.Println("🌐 Server running on :8080")
	if err := r.Run(":8080"); err != nil {
		fmt.Println("❌ Server failed:", err)
		os.Exit(1)
	}
}

func registerHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Password processing failed"})
			return
		}

		user.Password = string(hashed)

		if result := db.Create(&user); result.Error != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
	}
}

func loginHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		
	}
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": time.Now()})
}
