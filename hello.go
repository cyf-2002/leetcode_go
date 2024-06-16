package main

import "fmt"

func main() {
	c := search([]int{1, 3}, 3)
	fmt.Println(c)
}

func search(nums []int, target int) int {
	n := len(nums)
	if n == 1 {
		if target == nums[0] {
			return 0
		}
		return -1
	}
	// 找到第一段和第二段中间点的下标l
	l, r := 0, n-1
	for l < r {
		mid := (l + r) / 2
		if nums[mid] > nums[r] {
			l = mid + 1
		} else {
			r = mid
		}
	}
	// 判断target是在第一段还是第二段
	if target >= nums[0] {
		l = 0
	} else {
		r = n - 1
	}
	// 二分查找
	for l <= r {
		mid := (l + r) / 2
		if nums[mid] == target {
			return mid
		}
		if nums[mid] > target {
			r = mid - 1
		} else {
			l = mid + 1
		}
	}
	return -1
}
