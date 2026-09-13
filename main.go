package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Helper function to grab a service banner
func grabBanner(target string, timeout time.Duration) (string, error) {
	// Attempts a tcp connection to target and closes when done
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Sets the deadline for reading data
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Stores the buffer
	buf := make([]byte, 1024)
	
	// Reads in the buffer
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return "", err
	}

	// Returns the string from the buffer
	return string(buf[:n]), nil
}

// Function to handle the worker
func worker(id int, target string, jobs <-chan int, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Loops over each port in the ports
	for port := range jobs {
		// Converts the port number of a string
		portNum := strconv.Itoa(port)

		// Builds the target
		grabTarget := target + ":" + portNum

		// Grabs the banner
		banner, err := grabBanner(grabTarget, 3*time.Second)
		if err != nil {
			continue
		}

		result := fmt.Sprintf("Port: %d, banner: %s", port, banner)

		// Adds to the results
		results<-result
	}

	fmt.Printf("Worker %d finished\n", id)
}

func main() {
	// Stores the max number of workers and wait group
	const numWorkers = 100
	var wg sync.WaitGroup

	// Builds the channels for storing the ports and the results
	ports := make(chan int, 65535)
	results := make(chan string, 65535)

	// Starts the workers
	for workerId := 1; workerId <= numWorkers; workerId++ {
		wg.Add(1)

		go worker(workerId, "localhost", ports, results, &wg)
	}

	// Builds the jobs
	for port := 1; port <= 65535; port++ {
		// Adds the port to ports
		ports <- port
	}
	close(ports)

	// Waits for the wait group to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Loops over the results
	for r := range results {
		fmt.Println(r)
	}
}