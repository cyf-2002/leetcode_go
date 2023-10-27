package main

import (
	"fmt"
)

type MyStack struct {
	queue []int
}


func Constructor() MyStack {
	return MyStack{
		queue: make([]int, 0),
	}
}


func (this *MyStack) Push(x int)  {
	this.queue = append(this.queue, x)
}


func (this *MyStack) Pop() int {
	length := len(this.queue)
	for length > 1 {
		front := this.queue[0]
		this.queue = this.queue[1:]
		this.Push(front)
	}
	res := this.queue[0]
	this.queue = this.queue[1:]
	return res
}


func (this *MyStack) Top() int {
	return this.queue[0]
}


func (this *MyStack) Empty() bool {
	return len(this.queue) == 0
}


/**
 * Your MyStack object will be instantiated and called as such:
 * obj := Constructor();
 * obj.Push(x);
 * param_2 := obj.Pop();
 * param_3 := obj.Top();
 * param_4 := obj.Empty();
 */

func main() {
	fmt.Print("Hi")
}
