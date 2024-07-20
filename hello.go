package main

import "fmt"

func merge(nums1 []int, m int, nums2 []int, n int) {
	idx := m + n - 1
	for n > 0 {
		if m > 0 && nums1[m-1] > nums2[n-1] {
			nums1[idx] = nums1[m-1]
			m--
		} else {
			nums1[idx] = nums2[n-1]
			n--
		}
		idx--
	}
}

func main() {

	fmt.Println("hello world")
}
