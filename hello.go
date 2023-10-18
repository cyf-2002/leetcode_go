package main

import (
	"fmt"
)

func generateMatrix(n int) [][]int {
	matrix := make([][]int, n) // 创建一个包含n个切片的切片
	for i := 0; i < n; i++ {
		matrix[i] = make([]int, n) // 每个切片都创建一个包含n个元素的切片
	}

	offset := 0    //从offset开始每一圈的赋值
	loop := n / 2 //要转n / 2圈，画一个5 * 5矩阵很好理解
	count := 1
	for loop > 0 {
		for j := offset; j < n-offset-1; j++ { //坚持左闭右开原则
			matrix[offset][j] = count
			count++
		}
		for i := offset; i < n-offset-1; i++ {
			matrix[i][n-offset-1] = count
			count++
		}
		for j := n - offset - 1; j > offset; j-- {
			matrix[n-offset-1][j] = count
			count++
		}
		for i := n - offset - 1; i > offset; i-- {
			matrix[i][offset] = count
			count++
		}

		offset += 1 //第二圈赋值从(1, 1)开始，依次...
		loop -= 1
	}

	if n%2 == 1 {
		matrix[offset][offset] = count
	}
	return matrix
}

func main() {
	fmt.Print("Hello")
}
