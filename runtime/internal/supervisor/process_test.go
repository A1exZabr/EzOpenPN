package supervisor

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type concurrentProcess struct {
	mu            sync.Mutex
	current       int
	maxConcurrent int
}

func (process *concurrentProcess) Restart(context.Context) error {
	process.mu.Lock()
	process.current++
	if process.current > process.maxConcurrent {
		process.maxConcurrent = process.current
	}
	process.mu.Unlock()
	time.Sleep(20 * time.Millisecond)
	process.mu.Lock()
	process.current--
	process.mu.Unlock()
	return nil
}

func (process *concurrentProcess) Healthy() bool {
	return true
}

func TestRestartsAreSerialized(t *testing.T) {
	process := &concurrentProcess{}
	restarter := NewRestarter(process)
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		if err := restarter.Restart(context.Background()); err != nil {
			t.Errorf("first restart: %v", err)
		}
	}()
	go func() {
		defer group.Done()
		if err := restarter.Restart(context.Background()); err != nil {
			t.Errorf("second restart: %v", err)
		}
	}()
	group.Wait()

	if process.maxConcurrent != 1 {
		t.Fatalf("concurrent restarts = %d", process.maxConcurrent)
	}
}

type fakeChild struct {
	done       chan error
	signals    chan os.Signal
	exitOnTerm bool
	once       sync.Once
}

func newFakeChild(exitOnTerm bool) *fakeChild {
	return &fakeChild{
		done:       make(chan error, 1),
		signals:    make(chan os.Signal, 2),
		exitOnTerm: exitOnTerm,
	}
}

func (child *fakeChild) finish(err error) {
	child.once.Do(func() { child.done <- err })
}

func (child *fakeChild) Signal(signal os.Signal) error {
	child.signals <- signal
	if child.exitOnTerm {
		child.finish(errors.New("terminated"))
	}
	return nil
}

func (child *fakeChild) Kill() error {
	child.finish(errors.New("killed"))
	return nil
}

func (child *fakeChild) Wait() error {
	return <-child.done
}

type fakeStarter struct {
	mu       sync.Mutex
	children []*fakeChild
	started  chan *fakeChild
}

func (starter *fakeStarter) Start() (Child, error) {
	starter.mu.Lock()
	defer starter.mu.Unlock()
	if len(starter.children) == 0 {
		return nil, errors.New("no child")
	}
	child := starter.children[0]
	starter.children = starter.children[1:]
	starter.started <- child
	return child, nil
}

func testPolicy() processPolicy {
	return processPolicy{
		stopTimeout:    20 * time.Millisecond,
		stableDuration: time.Millisecond,
		failureWindow:  time.Minute,
		maxFailures:    5,
	}
}

func TestManagerRestartsTheFixedChildAndStopsOnCancellation(t *testing.T) {
	first := newFakeChild(true)
	second := newFakeChild(true)
	starter := &fakeStarter{
		children: []*fakeChild{first, second},
		started:  make(chan *fakeChild, 2),
	}
	manager := newProcessManager(starter, testPolicy())
	ctx, cancel := context.WithCancel(context.Background())
	runResult := make(chan error, 1)
	go func() { runResult <- manager.Run(ctx) }()
	<-starter.started

	if err := manager.Restart(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}
	<-starter.started
	if signal := <-first.signals; signal != syscall.SIGTERM {
		t.Fatalf("signal = %v", signal)
	}
	if !manager.Healthy() {
		t.Fatal("manager should be healthy after stable restart")
	}

	cancel()
	if err := <-runResult; err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestManagerStopsAfterRepeatedChildFailures(t *testing.T) {
	children := make([]*fakeChild, 0, 4)
	for range 4 {
		child := newFakeChild(false)
		child.finish(errors.New("crashed"))
		children = append(children, child)
	}
	starter := &fakeStarter{
		children: children,
		started:  make(chan *fakeChild, len(children)),
	}
	policy := testPolicy()
	policy.maxFailures = 2
	manager := newProcessManager(starter, policy)

	err := manager.Run(context.Background())

	if !errors.Is(err, ErrRepeatedFailures) {
		t.Fatalf("error = %v", err)
	}
}
