package main

import (
	"fmt"
	"math/rand"
	"time"
)

func main() {

	fmt.Println(rand.Intn(10))
	fmt.Println(rand.Intn(10))
	fmt.Println(rand.Intn(10))
	fmt.Println(rand.Intn(10))

}

func sortArray(nums []int) []int {
	quickSort(nums, 0, len(nums)-1)
	return nums
}

func quickSort(nums []int, l, r int) {
	if l < r {
		pivot := partition(nums, l, r)
		quickSort(nums, l, pivot-1)
		quickSort(nums, pivot+1, r)
	}
}

func partition(nums []int, l, r int) int {
	newRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	// 将pivot移到最右
	keyIndex := l + newRand.Intn(r-l+1)
	key := nums[keyIndex]
	nums[keyIndex], nums[r] = nums[r], nums[keyIndex]
	// [l, i) < key [i, r] >= key
	i, j := l, l
	for j < r {
		if nums[j] < key {
			nums[i], nums[j] = nums[j], nums[i]
			i++
		}
		j++
	}
	// 将pivot放到i处
	nums[i], nums[r] = nums[r], nums[i]
	return i
}
