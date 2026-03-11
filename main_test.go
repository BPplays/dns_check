package dns_check

import (
	"log"
	// "net/netip"
	"testing"
	"time"
)


func TestSprintTime(t *testing.T) {


	t.Run("testSprintTimeks", func(t *testing.T) {
		t.Parallel()
		s := sprintTime(50000 * time.Second)
		log.Println("sprintTime:", s)
		if s != "50ks" {
			t.Error()
		}
	})

	t.Run("testSprintTimes", func(t *testing.T) {
		t.Parallel()
		s := sprintTime(50000 * time.Millisecond)
		log.Println("sprintTime:", s)
		if s != "50s" {
			t.Error()
		}
	})

	t.Run("testSprintTimems", func(t *testing.T) {
		t.Parallel()
		s := sprintTime(50000 * time.Microsecond)
		log.Println("sprintTime should be 50ms:", s)
		if s != "50ms" {
			t.Error()
		}
	})

	t.Run("testSprintTimems", func(t *testing.T) {
		t.Parallel()
		tstr := "1s 504ms"
		s := sprintTime(1504435 * time.Microsecond)
		log.Printf("sprintTime should be %v ms: %v\n", tstr, s)
		if s != tstr {
			t.Error()
		}
	})


	// t.Run("testSprintTimems", func(t *testing.T) {
	// })

	t.Run("testSprintTimems", func(t *testing.T) {
		t.Parallel()
		s := sprintTime(150443 * time.Microsecond)
		log.Println("sprintTime should be 150ms 443µs:", s)
		if s != "150ms 443µs" {
			t.Error()
		}
	})

	t.Run("testSprintTimeμs", func(t *testing.T) {
		t.Parallel()
		s := sprintTime(50000 * time.Nanosecond)
		log.Println("sprintTime should be 50μs:", s)
		if s != "50µs" {
			t.Error()
		}
	})

	t.Run("testSprintTimens", func(t *testing.T) {
		t.Parallel()
		s := sprintTime(50 * time.Nanosecond)
		log.Println("sprintTime:", s)
		if s != "50ns" {
			t.Error()
		}
	})

	t.Run("testSprintTimens", func(t *testing.T) {
		tstr := "5ks 57s"
		s := ""
		st := time.Now()
		lps := 1000000
		if testing.Short() {
			lps = 100000
		}
		for range lps {
			s = sprintTime(5057052 * time.Millisecond)
		}
		sttotal := time.Since(st)
		log.Printf("sprintTime should be %v ms: %v\n", tstr, s)
		log.Printf("sprintTime %v takes %v, total: %v\n", tstr, sttotal / time.Duration(lps), sttotal)
		if s != tstr {
			t.Error()
		}
	})





}
