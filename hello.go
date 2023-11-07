package main

import (
	"fmt"
	"strconv"
)

// Definition for a binary tree node.
type TreeNode struct {
	Val   int
	Left  *TreeNode
	Right *TreeNode
}

var res []string

func dfs(root *TreeNode, path string) {
	if root == nil {
		return
	}
	if root.Left == nil && root.Right == nil {
		res = append(res, path+strconv.Itoa(root.Val))
	}
	if root.Left != nil {
		dfs(root.Left, path+strconv.Itoa(root.Val)+"->")
	}
	if root.Right != nil {
		dfs(root.Right, path+strconv.Itoa(root.Val)+"->")
	}
}

func binaryTreePaths(root *TreeNode) []string {
	res = []string{}
	dfs(root, "")
	return res
}

func main() {
	fmt.Print("hi")
}
