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

func invertTree(root *TreeNode) *TreeNode {
	if root == nil {
		return root
	}

	queue := []*TreeNode{root}
	for len(queue) > 0 {
		levelSize := len(queue)
		for i := 0; i < levelSize; i++ {
			if queue[i].Left != nil || queue[i].Right != nil {
				queue[i].Left, queue[i].Right = queue[i].Right, queue[i].Left
			}
			if queue[i].Left != nil {
				queue = append(queue, queue[i].Left)
			}
			if queue[i].Right != nil {
				queue = append(queue, queue[i].Right)
			}
		}

		queue = queue[levelSize:]
	}

	return root
}

func main() {
	fmt.Print("hi")
}
