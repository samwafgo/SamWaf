package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"sync"
)

// ReadFileConcurrently 读取单个文件的内容，并返回文件内容或错误
func ReadFileConcurrently(filePath string, wg *sync.WaitGroup, resultChan chan<- string, errChan chan<- error) {
	defer wg.Done() // 完成时减少 wait group 计数

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		errChan <- fmt.Errorf("file does not exist: %s", filePath)
		return
	}

	// 读取文件内容
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		errChan <- fmt.Errorf("error reading file %s: %v", filePath, err)
		return
	}

	// 返回文件内容
	resultChan <- string(content)
}

// ReadFile 读取指定文件的内容并返回结果或错误
func ReadFile(filePath string) (string, error) {
	var wg sync.WaitGroup

	// 创建用于返回结果和错误的通道
	resultChan := make(chan string, 1)
	errChan := make(chan error, 1)

	// 并发读取文件
	wg.Add(1)
	go ReadFileConcurrently(filePath, &wg, resultChan, errChan)

	// 等待文件读取完成
	wg.Wait()

	// 读取结果，避免在关闭通道后访问
	var result string
	var err error
	select {
	case result = <-resultChan:
		// 成功读取内容
	case err = <-errChan:
		// 读取出错
	}

	// 关闭通道
	close(resultChan)
	close(errChan)

	// 返回结果或错误
	if err != nil {
		return "", err
	}
	return result, nil
}
