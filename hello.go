package main

import (
	"fmt"
)

func spiralOrder(matrix [][]int) []int {
	rows := len(matrix)
	cols := len(matrix[0])
	order := make([]int, rows*cols)
	
	index := 0
	left, right, top, bottom := 0, cols-1, 0, rows-1

	for left <= right && top <= bottom {
		for column := left; column <= right; column++ {
			order[index] = matrix[top][column]
			index++
		}
		for row := top + 1; row <= bottom; row++ {
			order[index] = matrix[row][right]
			index++
		}
		//[1, 2, 3]不能进行如下遍历，所以需要加一个限制条件
		if left < right && top < bottom {
			for column := right - 1; column > left; column-- {
				order[index] = matrix[bottom][column]
				index++
			}
			for row := bottom; row > top; row-- {
				order[index] = matrix[row][left]
				index++
			}
		}
		left++
		right--
		top++
		bottom--
	}
	return order
}

func main() {
	matrix := [][]int{
		{1, 2, 3},
	}

	fmt.Print(spiralOrder(matrix))
}
