package main

type Person struct {
	Name string
	Age  int
}

func main() {
	p := Person{
		Age:  0,
		Name: "World",
	}

	p.Name = "Hello"
}
