package main

import (
	"container/heap"
	"fmt"
	"sort"
)

// 继承sort.Interface的方法
type IntHeap struct {
	sort.IntSlice
}

// 因为最大堆，所以覆盖Less方法，返回较大值
func (h IntHeap) Less(i, j int) bool {
	return h.IntSlice[i] > h.IntSlice[j]
}

func (h *IntHeap) Push(x interface{}) {
	h.IntSlice = append(h.IntSlice, x.(int))
}

func (h *IntHeap) Pop() interface{} {
	x := h.IntSlice[len(h.IntSlice)-1]
	h.IntSlice = h.IntSlice[:len(h.IntSlice)-1]
	return x
}

// 最小k个数
func getLeastNumbers(arr []int, k int) []int {
	if k == 0 {
		return []int{}
	}
	heapArr := make([]int, k)
	copy(heapArr, arr[:k])
	// 重要，取指针
	h := &IntHeap{IntSlice: heapArr}
	heap.Init(h)
	for i := k; i < len(arr); i++ {
		if x := arr[i]; x < h.IntSlice[0] {
			heap.Pop(h)
			heap.Push(h, x)
		}
	}
	return h.IntSlice

}

func main() {
	a := getLeastNumbers([]int{1, 2, 3, 4, 5}, 3)
	fmt.Println(a)
}
