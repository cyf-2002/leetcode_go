package main

import (
	"fmt"
)

// Definition for a binary tree node.
type TreeNode struct {
	Val   int
	Left  *TreeNode
	Right *TreeNode
}

var res [][]int

func findPath(root *TreeNode, targetSum int, path []int) {
	if root == nil {
		return
	}

	path = append(path, root.Val)
	targetSum -= root.Val
	if root.Left == nil && root.Right == nil && targetSum == 0 {
		cp := make([]int, len(path))
		copy(cp, path)
		res = append(res, cp)
	} else {
		findPath(root.Left, targetSum, path)
		findPath(root.Right, targetSum, path)
	}
}

func pathSum(root *TreeNode, targetSum int) [][]int {
	res = [][]int{}
	var path []int
	findPath(root, targetSum, path)
	return res
}

func main() {
	fmt.Print("hi")
}
