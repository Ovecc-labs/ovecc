package svc

import (
	"fmt"

	"example.com/app/store"
)

func Run() {
	fmt.Println("up")
	_ = store.DB{}
}
