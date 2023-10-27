package main

import (
	"fmt"
)

type ListNode struct {
	Val  int
	Next *ListNode
}

func removeNthFromEnd(head *ListNode, n int) *ListNode {
	dummyhead := &ListNode{
		Next: head,
	}
	slow, fast := dummyhead, dummyhead
	for n > 0 {
		fast = fast.Next
		n -= 1
	}
	for fast.Next != nil {
		slow = slow.Next
		fast = fast.Next
	}
	slow.Next = slow.Next.Next
	return dummyhead.Next
}

func main() {
	fmt.Print("Hi")
}
