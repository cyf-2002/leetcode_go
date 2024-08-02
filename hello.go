package main

import (
	"fmt"
	"sort"
)

type TreeNode struct {
	Val   int
	Left  *TreeNode
	Right *TreeNode
}

func buildTree(preorder []int, inorder []int) *TreeNode {
	if len(preorder) == 0 || len(inorder) == 0 {
		return nil
	}
	v := preorder[0]

	idx := sort.SearchInts(inorder, v)
	leftInorder, rightInorder := inorder[:idx], inorder[idx+1:]
	leftPreorder, rightPreorder := preorder[1:1+idx], preorder[1+idx:]

	return &TreeNode{
		Val:   v,
		Left:  buildTree(leftPreorder, leftInorder),
		Right: buildTree(rightPreorder, rightInorder),
	}
}

func main() {
	pre := []int{3, 9, 20, 15, 7}
	in := []int{9, 3, 15, 20, 7}
	idx := sort.SearchInts(in, 3)
	fmt.Println(idx)
	fmt.Println(buildTree(pre, in))

}
