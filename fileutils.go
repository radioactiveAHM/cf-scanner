package main

import (
	"log"
	"os"
	"sync"
)

type FileMutex struct {
	file   *os.File
	locker sync.Mutex
}

func (fm *FileMutex) Write(data string) error {
	fm.locker.Lock()
	defer fm.locker.Unlock()

	_, err := fm.file.WriteString(data)
	return err
}

func (fm *FileMutex) Close() error {
	fm.locker.Lock()
	defer fm.locker.Unlock()

	return fm.file.Close()
}

func resultFile(csv bool) *os.File {
	if csv {
		will_be_created := false
		_, exist := os.Stat("result.csv")
		if exist != nil {
			will_be_created = true
		}
		csv_file, err := os.OpenFile("result.csv", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		if will_be_created {
			csv_file.Write([]byte("ip:port,ping,latency,jitter,download\n"))
		}
		return csv_file
	} else {
		file, err := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		return file
	}
}
