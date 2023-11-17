package main

import (
	"fmt"
	"strconv"
	"strings"
)

func restoreIpAddresses(s string) []string {
	path := make([]string, 0, 4)
	res := make([]string, 0)

	var backtracking func(s string, start int)
	backtracking = func(s string, start int) {
		if len(path) == 4 {
			if start == len(s) {
				tmp := strings.Join(path, ".")
				res = append(res, tmp)
			}
			return
		}

		for i := start; i < len(s); i++ {
			if i != start && s[start] == '0' {
				break
			}
			str := s[start : i+1]
			num, _ := strconv.Atoi(str)
			if num >= 0 && num <= 255 {
				path = append(path, str)
				backtracking(s, i+1)
				path = path[:len(path)-1]
			} else {
				break
			}
		}
	}

	backtracking(s, 0)
	return res
}

func main() {
	res := restoreIpAddresses("25525511135")
	fmt.Print(res)
	fmt.Print("hi")
}
