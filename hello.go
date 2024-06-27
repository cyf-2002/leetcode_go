package main

import "fmt"

type Pair struct {
	multi int
	res   string
}

func decodeString(s string) string {
	st := make([]Pair, 0)
	res := ""
	multi := 0
	for _, str := range s {
		if str >= 'a' && str <= 'z' {
			res += string(str)
		} else if str >= '0' && str <= '9' {
			// str-'0' 是 int32 型
			multi = 10*multi + int(str-'0')
		} else if str == '[' {
			st = append(st, Pair{multi, res})
			multi, res = 0, ""
		} else {
			// str ==']'
			last := st[len(st)-1]
			st = st[:len(st)-1]
			res = last.res + repeatString(res, last.multi)
		}
	}

	return res
}

func repeatString(s string, multi int) string {
	res := ""
	for i := 0; i < multi; i++ {
		res += s
	}
	return res
}
func main() {
	res := decodeString("3[a]2[bc]")
	fmt.Println(res)
	a := '9' - '0'
	fmt.Println(a)
}
