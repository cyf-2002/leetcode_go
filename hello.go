package main

import (
	"fmt"
)

func combinationSum3(n int, k int) [][]int {
	path := make([]int, 0, k)
	res := make([][]int, 0)

	var backtracking func(n, k, start int)
	backtracking = func(n, k, start int) {
		if n == 0 && k == 0 {
			tmp := append([]int{}, path...)		//拷贝
			res = append(res, tmp)
			return
		}

		for i := start; i <= 9; i++ {
			if i > n {
				break
			}
			if 9-i+1 < k-len(path) {	//剪枝
				break
			}
			path = append(path, i)
			backtracking(n-i, k-1, i+1)
			path = path[:len(path)-1]	//回溯
		}
	}

	backtracking(n, k, 1)
	return res
}

func main() {
	res := combinationSum3(1, 4)
	fmt.Print(res)
}
