package main

import (
	"fmt"
	"math"
)

// Definition for a binary tree node.
type TreeNode struct {
	Val   int
	Left  *TreeNode
	Right *TreeNode
}

func getMinimumDifference(root *TreeNode) int {
	var nums []int

	var traversal func(root *TreeNode)
	traversal = func(root *TreeNode) {
		if root == nil {
			return
		}
		traversal(root.Left)
		nums = append(nums, root.Val)
		traversal(root.Right)
	}
	traversal(root)
	res := math.MaxInt64
	for i := 1; i < len(nums); i++ {
		if nums[i]-nums[i-1] < res {
			res = nums[i]-nums[i-1]
		}
	}
	return res
}

func main() {
	fmt.Print("hello")
}
