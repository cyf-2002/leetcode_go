package main

import (
	"fmt"
)

func reverseWords(s string) string {
	//去除所有空格并在相邻单词之间添加空格, 快慢指针。
	b := []byte(s)
	slow := 0
	for fast := 0; fast < len(s); fast++ {
		if b[fast] != ' ' {
			////手动控制空格，给单词之间添加空格。slow != 0说明不是第一个单词，需要在单词前添加空格。
			if slow != 0 {
				b[slow] = ' '
				slow++
			}
			for fast < len(s) && b[fast] != ' ' {
				b[slow] = b[fast]
				slow++
				fast++
			}
		}
	}
	b = b[:slow]
	//全部反转
	reverse(b)
	//再将单词反转
	for i := 0; i < len(b); i++ {
		j := i
		for j < len(b) && b[j] != ' ' {
			j++
		}
		reverse(b[i:j])
		i = j
	}
	return string(b)
}

func reverse(b []byte) {
	l, r := 0, len(b)-1
	for l < r {
		b[l], b[r] = b[r], b[l]
		l++
		r--
	}
}

func main() {
	c := reverseWords(" hello world heel     word ")
	fmt.Print(c)
}
