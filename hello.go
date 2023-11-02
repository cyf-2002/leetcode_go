package main

import (
	"fmt"
)

func getNext(next []int, s string) {
	j := 0
	next[0] = j
	for i := 1; i < len(s); i++ {
		//随便举个例子'acaacac'画一画清楚一点
		for j > 0 && s[i] != s[j] {
			j = next[j-1]
		}
		if s[i] == s[j] {
			j++
		}
		next[i] = j
	}
}

func strStr(haystack string, needle string) int {
	l := len(needle)
	next := make([]int, l)
	getNext(next, needle)
	j := 0
	for i := 0; i < len(haystack); i++ {
		for j > 0 && haystack[i] != needle[j] {
			j = next[j-1]
		}
		if haystack[i] == needle[j] {
			j++
		}
		if j == l {
			return i - l + 1
		}
	}
	return -1
}

func main() {
	fmt.Print("hi")
}
