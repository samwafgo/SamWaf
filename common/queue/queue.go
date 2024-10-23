package queue

import (
	"container/list"
	"sync"
)

type Queue struct {
	data  *list.List
	mutex sync.RWMutex
}

func NewQueue() *Queue {
	q := &Queue{data: list.New(), mutex: sync.RWMutex{}}
	return q
}

func (q *Queue) Enqueue(v interface{}) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	q.data.PushBack(v)

}

func (q *Queue) Dequeue() (interface{}, bool) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.data.Len() > 0 {
		element := q.data.Front()
		v := element.Value
		q.data.Remove(element)
		return v, true
	} else {
		return nil, false
	}
}
func (q *Queue) Size() int {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return q.data.Len()
}

func (q *Queue) Empty() bool {
	q.mutex.RLock()
	defer q.mutex.RUnlock()

	return q.data.Len() == 0
}
