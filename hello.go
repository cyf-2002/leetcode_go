package main

import (
	"fmt"
)

func intersection(nums1 []int, nums2 []int) []int {
	set := make(map[int]struct{}, 0)
	res := make([]int, 0)
	for _, num1 := range nums1 {
		if _, ok := set[num1]; !ok {
			set[num1] = struct{}{}
		}
	}
	for _, num2 := range nums2 {
		if _, ok := set[num2]; ok {
			res = append(res, num2)
			delete(set, num2)
		}
	}
	return res
}

func main() {
	fmt.Print("Hi")
}
