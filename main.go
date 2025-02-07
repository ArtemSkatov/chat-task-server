package main

import (
	"fmt"
	"strings"
	"time"

	_ "auth-server/docs" // Импортируйте сгенерированную документацию

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/swaggo/files"
	"github.com/swaggo/gin-swagger"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"sync"
)

// Конфигурация
const (
	jwtSecret     = "super-secret-key" // Замените в продакшене!
	accessExpire  = 15 * time.Minute
	refreshExpire = 7 * 24 * time.Hour
)

// Модели данных
type User struct {
	gorm.Model
	Username string `gorm:"unique" json:"username"`
	Password string `json:"-"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RefreshToken struct {
	gorm.Model
	UserID  uint   `gorm:"uniqueIndex"`
	Token   string `gorm:"unique"`
	Expires time.Time
}

// JWT Claims
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

type userLockMap struct {
	mu    sync.Mutex
	locks map[uint]*sync.Mutex
}

var locks = userLockMap{
	locks: make(map[uint]*sync.Mutex),
}

func main() {
	// Инициализация БД
	db, err := gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Автомиграция
	db.AutoMigrate(&User{}, &RefreshToken{})

	// Инициализация Gin
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		AllowCredentials: true, // Разрешить куки
		MaxAge:           12 * time.Hour,
	}))

	// Роуты
	api := r.Group("/api")
	{
		api.POST("/register", registerHandler(db))
		api.POST("/login", loginHandler(db))
		api.POST("/refresh", refreshHandler(db))
		api.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		api.POST("/logout", logoutHandler())
	}

	// Защищенные роуты
	auth := api.Group("/")
	auth.Use(authMiddleware())
	{
		auth.GET("/profile", infoProfileHandler(db))
	}

	// Запуск сервера
	r.Run(":8080")
}

// Получаем мьютекс для конкретного пользователя.
// Если его ещё нет, создаём новый.
func getUserLock(userID uint) *sync.Mutex {
	locks.mu.Lock()
	defer locks.mu.Unlock()
	if l, exists := locks.locks[userID]; exists {
		return l
	}
	newLock := &sync.Mutex{}
	locks.locks[userID] = newLock
	return newLock
}

// @Summary Выход пользователя
// @Description Выход пользователя стирание refresh_token
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} map[string]string "access_token и refresh_token"
// @Failure 400 {object} map[string]string "Ошибка валидации"
// @Failure 500 {object} map[string]string "Ошибка сервера"
// @Router /api/logout [post]
func logoutHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Удаление refresh token из куки
		c.SetCookie("refresh_token", "", -1, "/", "localhost", false, true)
		c.JSON(200, gin.H{"message": "Logged out successfully"})
	}
}

// @Summary Регистрация нового пользователя
// @Description Регистрирует нового пользователя и возвращает токены
// @Tags auth
// @Accept json
// @Produce json
// @Param input body RegisterRequest true "Данные для регистрации"
// @Success 200 {object} map[string]string "access_token и refresh_token"
// @Failure 400 {object} map[string]string "Ошибка валидации"
// @Failure 500 {object} map[string]string "Ошибка сервера"
// @Router /api/register [post]
func registerHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input RegisterRequest

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(400, gin.H{"error": "Invalid input"})
			return
		}

		// Хэширование пароля
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error hashing password"})
			return
		}

		// Создание пользователя
		user := User{
			Username: input.Username,
			Password: string(hashedPassword),
		}

		if err := db.Create(&user).Error; err != nil {
			c.JSON(400, gin.H{"error": "User already exists"})
			return
		}

		// Генерация токенов
		access, refresh, err := generateTokens(user.ID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error generating tokens"})
			return
		}

		saveRefreshToken(db, user.ID, refresh)

		c.SetCookie("refresh_token", refresh, int(refreshExpire.Seconds()), "/", "localhost", false, true)

		c.JSON(200, gin.H{
			"access_token": access,
		})
	}
}

// @Summary Логин пользователя
// @Description Авторизует пользователя и возвращает токены
// @Tags auth
// @Accept json
// @Produce json
// @Param input body LoginRequest true "Данные для входа"
// @Success 200 {object} map[string]string "access_token и refresh_token"
// @Failure 400 {object} map[string]string "Ошибка валидации"
// @Failure 401 {object} map[string]string "Неверные данные"
// @Failure 500 {object} map[string]string "Ошибка сервера"
// @Router /api/login [post]
func loginHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input LoginRequest

		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(400, gin.H{"error": "Invalid input"})
			return
		}

		// Поиск пользователя
		var user User
		if err := db.Where("username = ?", input.Username).First(&user).Error; err != nil {
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		// Проверка пароля
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		// Генерация токенов
		access, refresh, err := generateTokens(user.ID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error generating tokens"})
			return
		}

		saveRefreshToken(db, user.ID, refresh)

		// Установка refresh token в HTTP-only куку
		c.SetCookie("refresh_token", refresh, int(refreshExpire.Seconds()), "/", "localhost", false, true)

		c.JSON(200, gin.H{
			"access_token": access,
			"user_id":      user.ID,
		})
	}
}

// @Summary Получить профиль пользователя
// @Description Возвращает информацию о текущем пользователе
// @Tags user
// @Security ApiKeyAuth
// @Produce json
// @Success 200 {object} map[string]uint "user_id"
// @Failure 401 {object} map[string]string "Неавторизованный доступ"
// @Router /api/profile [get]
func infoProfileHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			return
		}

		// Приведение userID к uint
		userIDUint, ok := userID.(uint)
		if !ok {
			c.JSON(500, gin.H{"error": "Invalid user ID type"})
			return
		}

		var user User
		if err := db.First(&user, userIDUint).Error; err != nil {
			c.JSON(404, gin.H{"error": "User not found"})
			return
		}

		c.JSON(200, gin.H{
			"id":       user.ID,
			"username": user.Username,
		})
	}
}

// @Summary Переиздать access_token
// @Description Возвращает access_token
// @Tags user
// @Security ApiKeyAuth
// @Produce json
// @Success 200 {object} map[string]uint "user_id"
// @Failure 401 {object} map[string]string "Неавторизованный доступ"
// @Router /api/refresh [post]
func refreshHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		refreshToken, err := c.Cookie("refresh_token")
		if err != nil {
			c.JSON(400, gin.H{"error": "Refresh token is required"})
			return
		}
		claims, err := validateToken(refreshToken)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token"})
			return
		}

		userLock := getUserLock(claims.UserID)
		userLock.Lock()
		defer userLock.Unlock()

		// Логирование для отладки
		fmt.Printf("Received refresh token from cookie: %s\n", refreshToken)

		var token RefreshToken
		if err := db.Where("token = ? AND user_id = ?", refreshToken, claims.UserID).First(&token).Error; err != nil {
			fmt.Printf("DB token not found for user %d with token %s\n", claims.UserID, refreshToken)
			c.JSON(401, gin.H{"error": "Token revoked"})
			return
		}

		access, newRefresh, err := generateTokens(claims.UserID)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error generating tokens"})
			return
		}

		// Используем транзакцию для атомарного обновления
		if err := saveRefreshToken(db, claims.UserID, newRefresh); err != nil {
			c.JSON(500, gin.H{"error": "Error updating refresh token"})
			return
		}

		// Логирование нового токена
		fmt.Printf("Updated refresh token for user %d: %s\n", claims.UserID, newRefresh)

		c.SetCookie("refresh_token", newRefresh, int(refreshExpire.Seconds()), "/", "localhost", false, true)

		c.JSON(200, gin.H{
			"access_token": access,
			// Можно добавить новый refresh token, если хотите явно передавать клиенту
			// "refresh_token": newRefresh,
		})
	}
}

// Вспомогательные функции
func generateTokens(userID uint) (string, string, error) {
	// Access token
	accessClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessExpire)),
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	access, err := accessToken.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", "", err
	}

	// Refresh token
	refreshClaims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshExpire)),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refresh, err := refreshToken.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func saveRefreshToken(db *gorm.DB, userID uint, token string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Unscoped удаление предыдущих записей
		if err := tx.Unscoped().Where("user_id = ?", userID).Delete(&RefreshToken{}).Error; err != nil {
			return err
		}
		rt := RefreshToken{
			UserID:  userID,
			Token:   token,
			Expires: time.Now().Add(refreshExpire),
		}
		if err := tx.Create(&rt).Error; err != nil {
			return err
		}
		return nil
	})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" || !strings.HasPrefix(tokenString, "Bearer ") {
			c.JSON(401, gin.H{"error": "Missing or malformed token"})
			c.Abort()
			return
		}
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		claims, err := validateToken(tokenString)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("user_id", claims.UserID)
		c.Next()
	}
}

func validateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
