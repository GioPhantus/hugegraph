/*
 * Copyright 2017 HugeGraph Authors
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.baidu.hugegraph.task;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import javax.ws.rs.NotFoundException;

import com.alipay.remoting.util.ConcurrentHashSet;
import com.baidu.hugegraph.HugeGraphParams;
import com.baidu.hugegraph.backend.id.Id;
import com.baidu.hugegraph.config.CoreOptions;
import com.baidu.hugegraph.event.EventListener;
import com.baidu.hugegraph.exception.ConnectionException;
import com.baidu.hugegraph.job.EphemeralJob;
import com.baidu.hugegraph.meta.MetaManager;
import com.baidu.hugegraph.meta.lock.LockResult;
import com.baidu.hugegraph.structure.HugeVertex;
import com.baidu.hugegraph.task.TaskCallable.SysTaskCallable;
import com.baidu.hugegraph.util.E;
import com.baidu.hugegraph.util.Events;
import com.baidu.hugegraph.util.ExecutorUtil;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;

/**
 * EtcdTaskScheduler handle the distributed task by etcd
 * @author Scorpiour
 * @since 2022-01-01
 */
public class EtcdTaskScheduler extends TaskScheduler {

    private static final int CPU_COUNT = Runtime.getRuntime().availableProcessors();

    private final ExecutorService producer = ExecutorUtil.newFixedThreadPool(1, EtcdTaskScheduler.class.getName() + "-task-producer");

    private final Map<TaskPriority, BlockingQueue<Runnable>> taskQueueMap = new HashMap<>();

    private final ExecutorService taskExecutor;
    private final ExecutorService backupForLoadTaskExecutor;
    private final ExecutorService taskDBExecutor;

    private final ExecutorService executorService;

    private final Set<String> visitedTasks = new ConcurrentHashSet<>();

    private final Map<Id, HugeTask<?>> taskMap = new HashMap<>();


    private static final ImmutableSet<TaskStatus> EMPTY_SET = ImmutableSet.of();
    /**
     * State table
     */
    private static final Map<TaskStatus, ImmutableSet<TaskStatus>> TASK_STATUS_MAP = 
        new ImmutableMap.Builder<TaskStatus, ImmutableSet<TaskStatus>>() 
            .put(TaskStatus.UNKNOWN,
                EtcdTaskScheduler.EMPTY_SET)
            .put(TaskStatus.NEW,
                ImmutableSet.of(
                    TaskStatus.SCHEDULING))
            .put(TaskStatus.SCHEDULING,
                ImmutableSet.of(
                    TaskStatus.SCHEDULED, TaskStatus.CANCELLING, TaskStatus.FAILED))
            .put(TaskStatus.SCHEDULED,
                ImmutableSet.of(
                    TaskStatus.QUEUED, TaskStatus.CANCELLING))
            .put(TaskStatus.QUEUED,
                ImmutableSet.of(
                    TaskStatus.RUNNING, TaskStatus.PENDING, TaskStatus.CANCELLING))
            .put(TaskStatus.RUNNING,
                ImmutableSet.of(
                    TaskStatus.SUCCESS, TaskStatus.FAILED))
            .put(TaskStatus.CANCELLING,
                ImmutableSet.of(
                    TaskStatus.CANCELLED))
            .put(TaskStatus.CANCELLED,
                EtcdTaskScheduler.EMPTY_SET)
            .put(TaskStatus.SUCCESS,
                EtcdTaskScheduler.EMPTY_SET)
            .put(TaskStatus.FAILED,
                EtcdTaskScheduler.EMPTY_SET)
            .put(TaskStatus.PENDING,
                ImmutableSet.of(
                    TaskStatus.RESTORING
                ))
            .put(TaskStatus.RESTORING,
                ImmutableSet.of(
                    TaskStatus.QUEUED))
            .build();
 

    /**
     * Indicates that if the task has been checked already to reduce load
     */
    private final Set<String> checkedTasks = new HashSet<>();

    public EtcdTaskScheduler(
        HugeGraphParams graph,
        ExecutorService taskExecutor,
        ExecutorService backupForLoadTaskExecutor,
        ExecutorService taskDBExecutor,
        ExecutorService serverInfoDbExecutor,
        TaskPriority maxDepth
    ) {
        super(graph, serverInfoDbExecutor);
        this.taskExecutor = taskExecutor;
        this.backupForLoadTaskExecutor = backupForLoadTaskExecutor;
        this.taskDBExecutor = taskDBExecutor;

        this.eventListener =  this.listenChanges();

        BlockingQueue<Runnable> taskQueue = this.taskQueueMap.computeIfAbsent(maxDepth, v -> new LinkedBlockingQueue<>());

        this.executorService = new ThreadPoolExecutor(1, CPU_COUNT, 30, TimeUnit.SECONDS, taskQueue);
        MetaManager.instance().listenTaskAdded(this.graphSpace(), TaskPriority.NORMAL, this::taskEventHandler);
    }

    @Override
    public int pendingTasks() {
        return this
            .taskQueueMap
            .values()
            .stream()
            .collect(
                Collectors.summingInt(BlockingQueue::size)
            );
    }

    @Override
    public <V> void restoreTasks() {

    }

    @Override
    public <V> Future<?> schedule(HugeTask<V> task) {
        E.checkArgumentNotNull(task, "Task can't be null");

        if (task.callable() instanceof EphemeralJob) {
            task.status(TaskStatus.QUEUED);
            return this.submitEphemeralTask(task);
        }

        System.out.println("[Scheduler]====> Going to submit task " + task.id().asString());
        
        return this.submitTask(task);
    }

    @Override
    public <V> void cancel(HugeTask<V> task) {
        E.checkArgumentNotNull(task, "Task can't be null");

        if (task.completed() || task.cancelling()) {
            return;
        }

        MetaManager manager = MetaManager.instance();

        try {
            manager.lockTask(this.graphSpace(), task);
        } catch (Throwable e) {

        } finally {
            manager.unlockTask(this.graphSpace(), task);
        }
    }

    private <V> Id saveWithId(HugeTask<V> task) {
        task.scheduler(this);
        E.checkArgumentNotNull(task, "Task can't be null");
        HugeVertex v = this.call(() -> {
            // Construct vertex from task
            HugeVertex vertex = this.tx().constructVertex(task);
            // Delete index of old vertex to avoid stale index
            this.tx().deleteIndex(vertex);
            // Add or update task info to backend store
            return this.tx().addVertex(vertex);
        });
        return v.id();
    }

    @Override
    public <V> void save(HugeTask<V> task) {
        this.saveWithId(task);
    }

    @Override
    public <V> HugeTask<V> delete(Id id, boolean force) {
        MetaManager manager = MetaManager.instance();

        HugeTask<V> task = manager.getTask(this.graphSpace(), TaskPriority.NORMAL, id);
        if (null != task) {
            manager.deleteTask(this.graphSpace(), task); 
        }
        return task;
    }

    @Override 
    public void flushAllTask() {
        MetaManager.instance().flushAllTasks(this.graphSpace());
    }

    @Override
    public <V> HugeTask<V> task(Id id) {
        /** Here we have three scenarios:
         * 1. The task is handled by current node
         * 2. The task is handled by other node, but having snapshot here
         * 3. No any info here
         * As a result, we should distinguish them and processed separately
         * for case 1, we grab the info locally directly
         * for case 2, we grab the basic info and update related info, like status & progress
         * for case 3, we load everything from etcd and cached the snapshot locally for further use 
        */

        return null;
    }

    @Override
    public <V> Iterator<HugeTask<V>> tasks(List<Id> ids) {
        MetaManager manager = MetaManager.instance();
        List<String> allTasks = manager.listTasks(this.graphSpace(), TaskPriority.NORMAL);
        
        List<HugeTask<V>> tasks = allTasks.stream().map((jsonStr) -> {
            HugeTask<V> task = TaskSerializer.fromJson(jsonStr);
            // Attach callable info
            TaskCallable<?> callable = task.callable();
            // Attach graph info
            callable.graph(this.graph());

            task.progress(manager.getTaskProgress(this.graphSpace(), task));

            task.status(manager.getTaskStatus(this.graphSpace(), task));
            
            return task;
        }).collect(Collectors.toList());

        Iterator<HugeTask<V>> iterator = tasks.iterator();
        return iterator;
    }

    @Override
    public <V> Iterator<HugeTask<V>> tasks(TaskStatus status, long limit, String page) {
        MetaManager manager = MetaManager.instance();
        List<String> allTasks = manager.listTasksByStatus(this.graphSpace(), status);
        
        List<HugeTask<V>> tasks = allTasks.stream().map((jsonStr) -> {
            HugeTask<V> task = TaskSerializer.fromJson(jsonStr);
            // Attach callable info
            TaskCallable<?> callable = task.callable();
            // Attach graph info
            callable.graph(this.graph());

            task.progress(manager.getTaskProgress(this.graphSpace(), task));
            TaskStatus now = manager.getTaskStatus(this.graphSpace(), task);
            task.status(now);
            
            return task;
        }).collect(Collectors.toList());

        Iterator<HugeTask<V>> iterator = tasks.iterator();
        return iterator;
    }

    @Override
    public boolean close() {
        this.graph.loadSystemStore().provider().unlisten(this.eventListener);
        if (!this.taskDBExecutor.isShutdown()) {
            this.call(() -> {
                try {
                    this.tx().close();
                } catch (ConnectionException ignored) {
                    // ConnectionException means no connection established
                }
                this.graph.closeTx();
            });
        }
        return this.serverManager.close();
    }

    private <V> HugeTask<V> waitUntilTaskCompleted(Id id, long seconds,
                                                   long intervalMs)
                                                   throws TimeoutException {
        long passes = seconds * 1000 / intervalMs;
        HugeTask<V> task = null;
        for (long pass = 0;; pass++) {
            try {
                task = this.task(id);
            } catch (NotFoundException e) {
                if (task != null && task.completed()) {
                    assert task.id().asLong() < 0L : task.id();
                    sleep(intervalMs);
                    return task;
                }
                throw e;
            }
            if (task.completed()) {
                // Wait for task result being set after status is completed
                sleep(intervalMs);
                return task;
            }
            if (pass >= passes) {
                break;
            }
            sleep(intervalMs);
        }
        throw new TimeoutException(String.format(
                  "Task '%s' was not completed in %s seconds", id, seconds));
    }

    @Override
    public <V> HugeTask<V> waitUntilTaskCompleted(Id id, long seconds) throws TimeoutException {
        return this.waitUntilTaskCompleted(id, seconds, QUERY_INTERVAL);
    }

    @Override
    public <V> HugeTask<V> waitUntilTaskCompleted(Id id) throws TimeoutException {
        long timeout = this.graph.configuration()
                                 .get(CoreOptions.TASK_WAIT_TIMEOUT);
        return this.waitUntilTaskCompleted(id, timeout, 1L);
    }

    @Override
    public void waitUntilAllTasksCompleted(long seconds) throws TimeoutException {
        long passes = seconds * 1000 / QUERY_INTERVAL;
        int taskSize = 0;
        for (long pass = 0;; pass++) {
            taskSize = this.pendingTasks();
            if (taskSize == 0) {
                sleep(QUERY_INTERVAL);
                return;
            }
            if (pass >= passes) {
                break;
            }
            sleep(QUERY_INTERVAL);
        }
        throw new TimeoutException(String.format(
                  "There are still %s incomplete tasks after %s seconds",
                  taskSize, seconds));
        
    }

    private <V> Future<?> submitEphemeralTask(HugeTask<V> task) {
        assert !this.taskMap.containsKey(task.id()) : task;
        int size = this.taskMap.size();
        E.checkArgument(size < MAX_PENDING_TASKS,
            "Pending tasks size %s has exceeded the max limit %s",
            size + 1, MAX_PENDING_TASKS);
        task.scheduler(this);
        TaskCallable<V> callable = task.callable();
        callable.task(task);
        callable.graph(this.graph());
        if (callable instanceof SysTaskCallable) {
            ((SysTaskCallable<V>)callable).params(this.graph);
        }

        this.taskMap.put(task.id(), task);
        if (this.graph().mode().loading()) {
            return this.backupForLoadTaskExecutor.submit(task);   
        }
        return this.taskExecutor.submit(task);
    }

    private <V> Future<?> submitTask(HugeTask<V> task) {
        Thread ct = Thread.currentThread();
        task.scheduler(this);
        task.status(TaskStatus.SCHEDULING);

        // Save task first
        this.saveWithId(task);
        // Submit to etcd
        TaskCallable<V> callable = task.callable();
        callable.task(task);
        callable.graph(this.graph());
        if (callable instanceof SysTaskCallable) {
            ((SysTaskCallable<V>)callable).params(this.graph);
        }

        System.out.println(String.format("====> [Thread %d %s] start to create task %d", ct.getId(), ct.getName(), task.id().asLong()));
        return this.producer.submit(new TaskCreator<V>(task, this.graph));
    }

    @Override
    protected ServerInfoManager serverManager() {
        return this.serverManager;
    }

    private <V> V call(Runnable runnable) {
        return this.call(Executors.callable(runnable, null));
    }

    
    @Override
    protected <V> V call(Callable<V> callable) {
        return super.call(callable, this.taskDBExecutor);
    }

    @Override
    protected void taskDone(HugeTask<?> task) {
        try {
            this.serverManager.decreaseLoad(task.load());
        } catch (Exception e) {
            LOGGER.logCriticalError(e, "Failed to decrease load for task '{}' on server '{}'");
        }
    }

    private EventListener listenChanges() {
        // Listen store event: "store.inited"
        Set<String> storeEvents = ImmutableSet.of(Events.STORE_INITED);
        EventListener eventListener = event -> {
            // Ensure task schema create after system info initialized
            if (storeEvents.contains(event.name())) {
                this.call(() -> this.tx().initSchema());
                return true;
            }
            return false;
        };
        this.graph.loadSystemStore().provider().listen(eventListener);
        return eventListener;
    }

    private static boolean sleep(long ms) {
        try {
            Thread.sleep(ms);
            return true;
        } catch (InterruptedException ignored) {
            // Ignore InterruptedException
            return false;
        }
    }

    /**
     * Internal Producer is use to create task info to etcd
     */
    private static class TaskCreator<V> implements Runnable {

        private final HugeTask<V> task;
        private final HugeGraphParams graph;
        private final String graphSpace;

        public TaskCreator(HugeTask<V> task, HugeGraphParams graph) {
            this.task = task;
            this.graph = graph;
            this.graphSpace = this.graph.graph().graphSpace();
        }

        @Override
        public void run() {
            Thread ct = Thread.currentThread();
            System.out.println("====> Producer runner thread: " + ct.getId());
            MetaManager manager = MetaManager.instance();
            try {
                LockResult result = manager.lockTask(this.graphSpace, task);
                if (result.lockSuccess()) {
                    task.lockResult(result);
                    TaskStatus status = manager.getTaskStatus(this.graphSpace, task);
                    // Only unknown status indicates that the task has not been located
                    if (status != TaskStatus.UNKNOWN) {
                        System.out.println(String.format(">>>>> [Thread %d %s] task %d is scheduled already", ct.getId(), ct.getName(), task.id().asLong()));
                        return;
                    }
                    manager.createTask(graphSpace, task);
                    EtcdTaskScheduler.updateTaskStatus(graphSpace, task, TaskStatus.SCHEDULED);
                }
            } catch (Throwable e) {

            } finally {
                manager.unlockTask(this.graphSpace, task);
            }
        }
    }

    /**
     * Internal Producer is use to process task
     */
    private static class TaskRunner<V> implements Runnable {

        private final HugeTask<V> task;
        private final HugeGraphParams graph;
        private final String graphSpace;

        public TaskRunner(HugeTask<V> task, HugeGraphParams graph) {
            this.task = task;
            this.graph = graph;
            this.graphSpace = this.graph.graph().graphSpace();
        }

        @Override
        public void run() {
            Thread ct = Thread.currentThread();

            System.out.println("====> consumer runner thread: " + ct.getId());

            TaskStatus status = MetaManager.instance().getTaskStatus(this.graph.graph().graphSpace(), task);
            if (TaskStatus.COMPLETED_STATUSES.contains(status)) {
                System.out.println("====> task is complete! consumer runner finished: " + ct.getId());
                return;
            }

            EtcdTaskScheduler.updateTaskStatus(graphSpace, task, TaskStatus.RUNNING);
            
            System.out.println(String.format(">>>>> [Thread %d %s] going to run task %d", ct.getId(), ct.getName(), task.id().asLong()));
            this.task.run();

            EtcdTaskScheduler.updateTaskStatus(graphSpace, task, TaskStatus.SUCCESS);
            EtcdTaskScheduler.updateTaskProgress(graphSpace, task, 100);
            
            MetaManager.instance().unlockTask(this.graph.graph().graphSpace(), task);

            System.out.println(String.format(">>>>> [Thread %d %s] consumer run task %d finished", ct.getId(), ct.getName(), task.id().asLong()));
        }
    }

    private static boolean isTaskNextStatus(TaskStatus prevStatus, TaskStatus nextStatus) {
        return EtcdTaskScheduler.TASK_STATUS_MAP.get(prevStatus).contains(nextStatus);
    }


    /**
     * Internal TaskUpdater is used to update task status
     */
    private static void updateTaskStatus(String graphSpace, HugeTask<?> task, TaskStatus nextStatus) {
        MetaManager manager = MetaManager.instance();
        // Synchronize local status & remote status
        TaskStatus etcdStatus = manager.getTaskStatus(graphSpace, task);

        /**
         * local status different to etcd status, and delayed
         */
        if (!EtcdTaskScheduler.isTaskNextStatus(etcdStatus, task.status())) {
            task.status(etcdStatus);
        }
        // Ensure that next status is available
        TaskStatus prevStatus = task.status();
        if (EtcdTaskScheduler.isTaskNextStatus(prevStatus, nextStatus)) {
            task.status(nextStatus);
            manager.migrateTaskStatus(graphSpace, task, prevStatus);
        }
    }

    /**
     * Update task progress, make it always lead
     */
    private static void updateTaskProgress(String graphSpace, HugeTask<?> task, int nextProgress) {
        MetaManager manager = MetaManager.instance();
        int etcdProgress = manager.getTaskProgress(graphSpace, task);
        // push task current progress forward
        if (task.progress() < nextProgress) {
            task.progress(nextProgress);
        }
        if (etcdProgress > task.progress()) {
            task.progress(etcdProgress);
            return;
        }
        manager.updateTaskProgress(graphSpace, task);
    }

    /**
     * General handler of tasks
     * @param <T>
     * @param response
     */
    private <T> void taskEventHandler(T response) {

        Thread ct = Thread.currentThread();

        System.out.println("====> Normal handler Current thread: " + ct.getId() + " name " + Thread.currentThread().getName());
        
        // Prepare events
        MetaManager manager = MetaManager.instance();
        Map<String, String> events = manager.extractKVFromResponse(response);

        // Since the etcd event is not a single task, we should cope with them one by one
        for(Map.Entry<String, String> entry : events.entrySet()) {
            System.out.println(String.format("====> [Thread %d %s] task info %s, %s", ct.getId(), ct.getName(), entry.getKey(), entry.getValue()));
            // If the task has been checked already, skip
            if (this.checkedTasks.contains(entry.getKey())) {
                System.out.println(String.format("====> [Thread %d %s] task info %s has been executed", ct.getId(), ct.getName(), entry.getKey()));
                continue;
            }
            try {
                // Deserialize task
                HugeTask<?> task = TaskSerializer.fromJson(entry.getValue());
                System.out.println(String.format("====> [Thread %d %s] try to lock %s", ct.getId(), ct.getName(), entry.getKey()));

                // Try to lock the task
                LockResult result = manager.lockTask(this.graphSpace(), task);
                if (result.lockSuccess()) {
                    // Persist the lockResult instance to task for keepAlive and unlock
                    task.lockResult(result);
                    // The task has been visited once
                    if (this.visitedTasks.contains(task.id().asString())) {
                        System.out.println(String.format("====> [Thread %d %s] found task %s has been visited", ct.getId(), ct.getName(), entry.getKey()));
                        manager.unlockTask(this.graphSpace(), task);
                        continue;
                    }
                    // Mark the task is visited already
                    this.visitedTasks.add(task.id().asString());
                    // Grab status info from task
                    TaskStatus currentStatus = manager.getTaskStatus(this.graphSpace(), task);
                    // If task has been occupied, skip also
                    if (TaskStatus.OCCUPIED_STATUS.contains(currentStatus)) {
                        System.out.println(String.format("====> [Thread %d %s] found task %s has been done", ct.getId(), ct.getName(), entry.getKey()));
                        this.visitedTasks.add(task.id().asString());
                        manager.unlockTask(this.graphSpace(), task);
                        continue;
                    }
                    System.out.println(String.format("=====> Grab task %s lock success", task.id().asString()));
                    // Attach callable info
                    TaskCallable<?> callable = task.callable();
                    // Attach priority info
                    MetaManager.instance().attachTaskInfo(task, entry.getKey());
                    // Attach graph info
                    callable.graph(this.graph());
                    // Update status to queued
                    EtcdTaskScheduler.updateTaskStatus(this.graphSpace(), task, TaskStatus.QUEUED);
                    // run it
                    this.taskExecutor.submit(new TaskRunner<>(task, this.graph));
                } else {
                    System.out.println("=====> Grab task lock failed");
                }
            } catch (Exception e) {
                System.out.println("=====> Grab task lock error");
                System.out.println(e);
                System.out.println(e.getStackTrace());
            }
        }

        System.out.println(String.format("====> [Thread %d %s] handle response end", ct.getId(), ct.getName()));
    }
}