package main

import (
	"fmt"
	"sort"
)

func combinationSum2(candidates []int, target int) [][]int {
	sort.Ints(candidates)
	path := make([]int, 0)
	res := make([][]int, 0)

	var backtracking func(target int, start int)
	backtracking = func(target int, start int) {
		if target == 0 {
			tmp := append([]int{}, path...)
			res = append(res, tmp)
			return
		}

		for i := start; i < len(candidates); i++ {
			if candidates[i] > target {
				break
			}
			if i > start && candidates[i] == candidates[i-1] {
				continue
			}
			path = append(path, candidates[i])
			backtracking(target-candidates[i], i+1)
			path = path[:len(path)-1]
		}
	}

	backtracking(target, 0)
	return res
}

func main() {
	fmt.Print("hi")
}
