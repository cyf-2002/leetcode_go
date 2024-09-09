package main

import "fmt"

func main() {
	post := map[int][]int{}
	post[0] = append(post[0], 1)

	fmt.Println(post)
}
