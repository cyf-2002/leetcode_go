package main

import (
	"fmt"
	"github.com/emirpasic/gods/sets/treeset"
)

func main() {
	set := treeset.NewWithIntComparator()
	set.Add(1)
	set.Add(3, 4, 5, 2)
	fmt.Print(set)
	fmt.Print("hi")
}
