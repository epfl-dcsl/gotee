package main

import (
	"fmt"
	"gosec"
	"hw"
)

func main() {
	done := make(chan bool)

	// A regular goroutine
	fmt.Println("From an untrusted domain:")
	go hw.HelloWorld(done)
	<-done

	// Now a secured routine
	fmt.Println("From a trusted domain:")
	gosecure hw.HelloWorld(done)
	<- done
}
