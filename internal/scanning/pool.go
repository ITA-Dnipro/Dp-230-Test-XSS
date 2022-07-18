package scanning

import (
	"context"
	"sync"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/model"
)

func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan Queries, results chan<- *model.PoC) {
	defer wg.Done()
	for {
		select {
		case job, ok := <-jobs:
			if !ok {
				return
			}
			results <- job.check(ctx)
		case <-ctx.Done():
			results <- nil
			return
		}
	}
}

type WorkerPool struct {
	workersCount int
	jobs         chan Queries
	results      chan *model.PoC
	Done         chan struct{}
}

func NewWorkerPool(wcount int) WorkerPool {
	return WorkerPool{
		workersCount: wcount,
		jobs:         make(chan Queries, wcount),
		results:      make(chan *model.PoC, wcount),
		Done:         make(chan struct{}),
	}
}

func (wp WorkerPool) Run(ctx context.Context) {
	var wg sync.WaitGroup

	for i := 0; i < wp.workersCount; i++ {
		wg.Add(1)
		go worker(ctx, &wg, wp.jobs, wp.results)
	}

	wg.Wait()
	close(wp.Done)
	close(wp.results)
}

func (wp WorkerPool) Results() <-chan *model.PoC {
	return wp.results
}

func (wp WorkerPool) GenerateFrom(queries []Queries) {
	for i := range queries {
		wp.jobs <- queries[i]
	}
	close(wp.jobs)
}
