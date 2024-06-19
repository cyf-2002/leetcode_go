package main

import (
	"fmt"
)

func main() {
	var a, b int
	_, err := fmt.Scan(&a, &b)
	if err != nil {
		return
	}
	fmt.Println(a, b)

}
