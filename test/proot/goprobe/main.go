// The Go runtime under the loader (test_go.py): what broke Go programs, in
// one static binary that has its own svc instructions. Usage: goprobe DIR
// (a writable directory); goprobe child N (run by the exec case).
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func check(ok bool, what string, detail ...any) {
	if !ok {
		fmt.Println("FAIL", what, fmt.Sprint(detail...))
		os.Exit(1)
	}
	fmt.Println("ok", what)
}

// Many goroutines (small stacks) in file calls at once.
func files(dir string) {
	var wg sync.WaitGroup
	var bad atomic.Int64
	for g := 0; g < 64; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			sub := filepath.Join(dir, fmt.Sprint("g", g))
			if os.Mkdir(sub, 0o755) != nil {
				bad.Add(1)
				return
			}
			for i := 0; i < 200; i++ {
				p := filepath.Join(sub, fmt.Sprint("f", i))
				if os.WriteFile(p, []byte(p), 0o644) != nil {
					bad.Add(1)
				}
				if b, err := os.ReadFile(p); err != nil || string(b) != p {
					bad.Add(1)
				}
				if _, err := os.Stat(p); err != nil {
					bad.Add(1)
				}
			}
			if e, err := os.ReadDir(sub); err != nil || len(e) != 200 {
				bad.Add(1)
			}
			if os.RemoveAll(sub) != nil {
				bad.Add(1)
			}
		}(g)
	}
	wg.Wait()
	check(bad.Load() == 0, "64 goroutines x 200 files", bad.Load())
}

// Goroutines blocked in open of FIFOs: one thread each, all in the payload.
func fifos(dir string) {
	const n = 200
	var wg sync.WaitGroup
	var opened atomic.Int64
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, fmt.Sprint("fifo", i))
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			check(false, "mkfifo", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f, err := os.OpenFile(p, os.O_RDONLY, 0); err == nil {
				opened.Add(1)
				f.Close()
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, fmt.Sprint("fifo", i))
		if fd, err := syscall.Open(p, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			syscall.Close(fd)
		}
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		os.Remove(filepath.Join(dir, fmt.Sprint("fifo", i)))
	}
	check(opened.Load() == n, "200 goroutines blocked in open at once", opened.Load())
}

// Signals while goroutines spin and allocate (async preemption is SIGURG).
func signals() {
	ch := make(chan os.Signal, 256)
	signal.Notify(ch, syscall.SIGUSR1)
	stop := make(chan struct{})
	var spins atomic.Int64
	for i := 0; i < 4; i++ {
		go func() {
			x := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				for j := 0; j < 1e6; j++ {
					x += j
				}
				_ = make([]byte, 4096)
				spins.Add(1)
			}
		}()
	}
	for i := 0; i < 200; i++ {
		syscall.Kill(os.Getpid(), syscall.SIGUSR1)
		if i%20 == 0 {
			runtime.GC()
		}
	}
	got := 0
	deadline := time.After(5 * time.Second)
loop:
	for got < 1 {
		select {
		case <-ch:
			got++
		case <-deadline:
			break loop
		}
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	check(got >= 1 && spins.Load() > 0, "signals and preemption while goroutines run", got, " ", spins.Load())
}

// os/exec from goroutines: vfork on the goroutine's stack.
func execs(self string) {
	var wg sync.WaitGroup
	var bad atomic.Int64
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := exec.Command(self, "child", fmt.Sprint(i)).Output()
			if err != nil || string(out) != fmt.Sprint("child ", i, "\n") {
				bad.Add(1)
			}
		}(i)
	}
	wg.Wait()
	check(bad.Load() == 0, "16 concurrent os/exec", bad.Load())
}

// Loopback TCP with concurrent clients.
func network() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		check(false, "listen", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				line, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte("echo " + line))
				c.Close()
			}(c)
		}
	}()
	var wg sync.WaitGroup
	var bad atomic.Int64
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				bad.Add(1)
				return
			}
			fmt.Fprintf(c, "%d\n", i)
			line, _ := bufio.NewReader(c).ReadString('\n')
			if line != fmt.Sprintf("echo %d\n", i) {
				bad.Add(1)
			}
			c.Close()
		}(i)
	}
	wg.Wait()
	ln.Close()
	check(bad.Load() == 0, "32 loopback TCP clients", bad.Load())
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "child" {
		fmt.Println("child", os.Args[2])
		return
	}
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	dir := os.Args[1]
	runtime.GOMAXPROCS(8)
	files(dir)
	fifos(dir)
	signals()
	execs(os.Args[0])
	network()
	fmt.Println("goprobe passed", runtime.Version())
}
