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

func isValidBST(root *TreeNode) bool {
    nums := make([]int, 0)

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

    for i := 1; i < len(nums); i++ {
        if nums[i] <= nums[i-1] {
            return false
        }
    }

    return true
}


func main() {
	fmt.Print("hello")
}
