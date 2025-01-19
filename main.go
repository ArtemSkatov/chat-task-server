package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Print("start")

	r := gin.Default()

	r.GET("/test", func(ctx *gin.Context) {
		fmt.Print("get")
	})

	r.Run(":8080")
}
