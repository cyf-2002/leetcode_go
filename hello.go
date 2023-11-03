package main

import (
	"fmt"
)

func isValid(s string) bool {
	set := map[byte]byte{')': '(', '}': '{', ']': '['}
	stack := make([]byte, 0)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '(' || ch == '{' || ch == '[' {
			stack = append(stack, ch)
		} else {
			l := len(stack) - 1
			if l < 0 {
				return false
			}
			if stack[l] == set[ch] {
				stack = stack[:l]
			} else {
				return false
			}
		}
	}
	return len(stack) == 0
}

func main() {
	fmt.Print("hi")
}
