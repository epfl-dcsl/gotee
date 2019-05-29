package hw

import "fmt"

func HelloWorld(done chan bool) {
	fmt.Println("Hello World!")
	done <- true
}
