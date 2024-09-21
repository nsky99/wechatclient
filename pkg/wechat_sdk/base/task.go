package base

import (
	"fmt"
	"sync"
	"time"
	"wechatclient/pkg/wechat_sdk/mmscene/scene"
)

type Task struct {
	Id        int
	CmdId     uint32              // 要执行的命令
	Scene     scene.INetSceneBase // 命令对象
	TaskId    uint32              // 就是seqnum
	AckChan   chan bool           // 等待ack的通道
	RecvData  []byte              // 接收到的数据
	CreatedAt time.Time           // 任务创建时间
}

type TaskMgr struct {
	SendQueue chan *Task // 客户端请求
	RecvQueue chan *Task // 服务端响应
	PushQueue chan *Task // 服务端推送
	done      chan struct{}
	wg        sync.WaitGroup
}

func NewTaskQueue(size uint32) *TaskMgr {
	return &TaskMgr{
		SendQueue: make(chan *Task, size),
		RecvQueue: make(chan *Task, size),
		done:      make(chan struct{}),
	}
}

func (q *TaskMgr) StartWorker(sendWork func(task *TaskMgr) error, recvWork func(task *TaskMgr) error) {
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		for {
			if sendWork(q) != nil {
				return
			}
		}
	}()
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		for {
			if recvWork(q) != nil {
				return
			}
		}
	}()
}

func (q *TaskMgr) StartTask(task *Task) error {
	task.AckChan = make(chan bool, 1) // 初始化AckCha
	task.CreatedAt = time.Now()

	select {
	case q.SendQueue <- task:
		<-task.AckChan
		return nil
	default:
		return fmt.Errorf("TaskQueue is full")
	}
}

func (q *TaskMgr) Stop() {
	close(q.SendQueue)
	close(q.RecvQueue)
	q.wg.Wait()
	close(q.done)
}
