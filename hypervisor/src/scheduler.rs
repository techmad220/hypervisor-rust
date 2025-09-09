//! Advanced scheduler implementation with CFS and priority-based scheduling
//! Supports multiple scheduling policies and real-time tasks

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::{Mutex, RwLock};
use core::cmp::{Ordering, Reverse};
use core::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering as AtomicOrdering};
use lazy_static::lazy_static;
use x86_64::instructions::interrupts;

/// Scheduling policies
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchedPolicy {
    /// Completely Fair Scheduler (default for normal tasks)
    CFS,
    /// Real-time FIFO (runs until blocked/preempted by higher priority)
    RealTimeFifo,
    /// Real-time Round Robin (time-sliced real-time)
    RealTimeRR,
    /// Batch processing (CPU-intensive, no interactivity)
    Batch,
    /// Idle (runs only when nothing else to run)
    Idle,
    /// Deadline scheduling (EDF - Earliest Deadline First)
    Deadline,
}

/// Task priority levels
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Priority(pub i32);

impl Priority {
    pub const MAX_RT: i32 = 99;      // Highest real-time priority
    pub const MIN_RT: i32 = 0;       // Lowest real-time priority  
    pub const DEFAULT: i32 = 0;      // Default nice value
    pub const MIN_NICE: i32 = -20;   // Highest normal priority
    pub const MAX_NICE: i32 = 19;    // Lowest normal priority
    
    pub fn new(value: i32) -> Self {
        Priority(value.clamp(Self::MIN_NICE, Self::MAX_RT))
    }
    
    pub fn is_realtime(&self) -> bool {
        self.0 >= Self::MIN_RT && self.0 <= Self::MAX_RT
    }
}

/// Task state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TaskState {
    /// Ready to run
    Runnable,
    /// Currently running on CPU
    Running,
    /// Waiting for I/O or event
    Waiting,
    /// Stopped (suspended)
    Stopped,
    /// Zombie (terminated but not reaped)
    Zombie,
    /// New (not yet started)
    New,
}

/// Task statistics
#[derive(Debug, Clone)]
pub struct TaskStats {
    /// Total time on CPU (nanoseconds)
    pub exec_time: AtomicU64,
    /// Virtual runtime for CFS
    pub vruntime: AtomicU64,
    /// Number of voluntary context switches
    pub voluntary_switches: AtomicU64,
    /// Number of involuntary context switches  
    pub involuntary_switches: AtomicU64,
    /// Last time scheduled
    pub last_scheduled: AtomicU64,
    /// Time spent waiting
    pub wait_time: AtomicU64,
    /// Time spent in system calls
    pub system_time: AtomicU64,
    /// Time spent in user mode
    pub user_time: AtomicU64,
}

impl TaskStats {
    fn new() -> Self {
        Self {
            exec_time: AtomicU64::new(0),
            vruntime: AtomicU64::new(0),
            voluntary_switches: AtomicU64::new(0),
            involuntary_switches: AtomicU64::new(0),
            last_scheduled: AtomicU64::new(0),
            wait_time: AtomicU64::new(0),
            system_time: AtomicU64::new(0),
            user_time: AtomicU64::new(0),
        }
    }
}

/// CPU affinity mask
#[derive(Debug, Clone)]
pub struct CpuSet {
    mask: u64,
}

impl CpuSet {
    pub fn new() -> Self {
        Self { mask: !0 } // All CPUs by default
    }
    
    pub fn single(cpu: usize) -> Self {
        Self { mask: 1 << cpu }
    }
    
    pub fn set(&mut self, cpu: usize) {
        self.mask |= 1 << cpu;
    }
    
    pub fn clear(&mut self, cpu: usize) {
        self.mask &= !(1 << cpu);
    }
    
    pub fn is_set(&self, cpu: usize) -> bool {
        (self.mask & (1 << cpu)) != 0
    }
}

/// Deadline scheduling parameters
#[derive(Debug, Clone, Copy)]
pub struct DeadlineParams {
    /// Relative deadline (nanoseconds)
    pub deadline: u64,
    /// Execution time budget (nanoseconds)
    pub runtime: u64,
    /// Period (nanoseconds)
    pub period: u64,
    /// Absolute deadline for current period
    pub abs_deadline: u64,
    /// Remaining runtime in current period
    pub remaining_runtime: u64,
}

/// Task control block
pub struct Task {
    /// Task ID
    pub tid: usize,
    /// Parent task ID
    pub parent_tid: Option<usize>,
    /// Task name
    pub name: String,
    /// Current state
    pub state: RwLock<TaskState>,
    /// Scheduling policy
    pub policy: SchedPolicy,
    /// Priority/nice value
    pub priority: Priority,
    /// CPU affinity
    pub cpu_affinity: RwLock<CpuSet>,
    /// Statistics
    pub stats: TaskStats,
    /// Time slice remaining (nanoseconds)
    pub time_slice: AtomicU64,
    /// Deadline parameters (if using deadline scheduling)
    pub deadline_params: Option<RwLock<DeadlineParams>>,
    /// Stack pointer
    pub stack_ptr: AtomicUsize,
    /// Instruction pointer
    pub instruction_ptr: AtomicUsize,
    /// Flags
    pub flags: AtomicU64,
    /// Exit code
    pub exit_code: AtomicU64,
}

impl Task {
    pub fn new(tid: usize, name: String, policy: SchedPolicy, priority: Priority) -> Self {
        Self {
            tid,
            parent_tid: None,
            name,
            state: RwLock::new(TaskState::New),
            policy,
            priority,
            cpu_affinity: RwLock::new(CpuSet::new()),
            stats: TaskStats::new(),
            time_slice: AtomicU64::new(DEFAULT_TIME_SLICE),
            deadline_params: None,
            stack_ptr: AtomicUsize::new(0),
            instruction_ptr: AtomicUsize::new(0),
            flags: AtomicU64::new(0),
            exit_code: AtomicU64::new(0),
        }
    }
    
    /// Calculate weight for CFS scheduling
    pub fn weight(&self) -> u64 {
        const NICE_0_WEIGHT: u64 = 1024;
        const WEIGHT_RATIO: f64 = 1.25;
        
        let nice = self.priority.0.clamp(Priority::MIN_NICE, Priority::MAX_NICE);
        let delta = nice - Priority::DEFAULT;
        
        if delta == 0 {
            NICE_0_WEIGHT
        } else if delta > 0 {
            (NICE_0_WEIGHT as f64 / WEIGHT_RATIO.powi(delta)) as u64
        } else {
            (NICE_0_WEIGHT as f64 * WEIGHT_RATIO.powi(-delta)) as u64
        }
    }
    
    /// Update virtual runtime for CFS
    pub fn update_vruntime(&self, delta: u64, total_weight: u64) {
        let weight = self.weight();
        let vruntime_delta = (delta * NICE_0_WEIGHT) / weight;
        self.stats.vruntime.fetch_add(vruntime_delta, AtomicOrdering::Relaxed);
    }
}

/// Default time slice in nanoseconds (10ms)
const DEFAULT_TIME_SLICE: u64 = 10_000_000;
const NICE_0_WEIGHT: u64 = 1024;

/// Per-CPU run queue
pub struct RunQueue {
    /// CPU ID this queue belongs to
    cpu_id: usize,
    /// Current running task
    current: Option<Arc<Task>>,
    /// CFS red-black tree (simulated with BTreeMap ordered by vruntime)
    cfs_tasks: BTreeMap<(u64, usize), Arc<Task>>,
    /// Real-time FIFO queues (one per priority level)
    rt_fifo: Vec<VecDeque<Arc<Task>>>,
    /// Real-time round-robin queues
    rt_rr: Vec<VecDeque<Arc<Task>>>,
    /// Deadline queue (ordered by absolute deadline)
    deadline_queue: BTreeMap<(u64, usize), Arc<Task>>,
    /// Batch queue
    batch_queue: VecDeque<Arc<Task>>,
    /// Idle task
    idle_task: Option<Arc<Task>>,
    /// Total weight of CFS tasks
    total_weight: AtomicU64,
    /// Number of running tasks
    nr_running: AtomicUsize,
    /// Minimum vruntime in CFS tree
    min_vruntime: AtomicU64,
    /// Last schedule time
    last_schedule: AtomicU64,
    /// Load average
    load_avg: AtomicU64,
}

impl RunQueue {
    pub fn new(cpu_id: usize) -> Self {
        Self {
            cpu_id,
            current: None,
            cfs_tasks: BTreeMap::new(),
            rt_fifo: vec![VecDeque::new(); 100],
            rt_rr: vec![VecDeque::new(); 100],
            deadline_queue: BTreeMap::new(),
            batch_queue: VecDeque::new(),
            idle_task: None,
            total_weight: AtomicU64::new(0),
            nr_running: AtomicUsize::new(0),
            min_vruntime: AtomicU64::new(0),
            last_schedule: AtomicU64::new(0),
            load_avg: AtomicU64::new(0),
        }
    }
    
    /// Enqueue a task
    pub fn enqueue(&mut self, task: Arc<Task>) {
        let state = task.state.read();
        if *state != TaskState::Runnable {
            return;
        }
        drop(state);
        
        match task.policy {
            SchedPolicy::CFS => {
                let vruntime = task.stats.vruntime.load(AtomicOrdering::Relaxed);
                self.cfs_tasks.insert((vruntime, task.tid), task.clone());
                self.total_weight.fetch_add(task.weight(), AtomicOrdering::Relaxed);
                
                // Update min_vruntime
                if let Some(((min_vr, _), _)) = self.cfs_tasks.iter().next() {
                    self.min_vruntime.store(*min_vr, AtomicOrdering::Relaxed);
                }
            },
            SchedPolicy::RealTimeFifo => {
                let prio = task.priority.0.clamp(0, 99) as usize;
                self.rt_fifo[prio].push_back(task);
            },
            SchedPolicy::RealTimeRR => {
                let prio = task.priority.0.clamp(0, 99) as usize;
                self.rt_rr[prio].push_back(task);
            },
            SchedPolicy::Deadline => {
                if let Some(ref params) = task.deadline_params {
                    let deadline = params.read().abs_deadline;
                    self.deadline_queue.insert((deadline, task.tid), task);
                }
            },
            SchedPolicy::Batch => {
                self.batch_queue.push_back(task);
            },
            SchedPolicy::Idle => {
                self.idle_task = Some(task);
            },
        }
        
        self.nr_running.fetch_add(1, AtomicOrdering::Relaxed);
    }
    
    /// Dequeue a task
    pub fn dequeue(&mut self, task: &Arc<Task>) {
        match task.policy {
            SchedPolicy::CFS => {
                let vruntime = task.stats.vruntime.load(AtomicOrdering::Relaxed);
                self.cfs_tasks.remove(&(vruntime, task.tid));
                self.total_weight.fetch_sub(task.weight(), AtomicOrdering::Relaxed);
            },
            SchedPolicy::RealTimeFifo => {
                let prio = task.priority.0.clamp(0, 99) as usize;
                self.rt_fifo[prio].retain(|t| t.tid != task.tid);
            },
            SchedPolicy::RealTimeRR => {
                let prio = task.priority.0.clamp(0, 99) as usize;
                self.rt_rr[prio].retain(|t| t.tid != task.tid);
            },
            SchedPolicy::Deadline => {
                if let Some(ref params) = task.deadline_params {
                    let deadline = params.read().abs_deadline;
                    self.deadline_queue.remove(&(deadline, task.tid));
                }
            },
            SchedPolicy::Batch => {
                self.batch_queue.retain(|t| t.tid != task.tid);
            },
            SchedPolicy::Idle => {
                if let Some(ref idle) = self.idle_task {
                    if idle.tid == task.tid {
                        self.idle_task = None;
                    }
                }
            },
        }
        
        self.nr_running.fetch_sub(1, AtomicOrdering::Relaxed);
    }
    
    /// Pick next task to run
    pub fn pick_next(&mut self) -> Option<Arc<Task>> {
        // Check deadline tasks first (EDF)
        if let Some(((_, tid), task)) = self.deadline_queue.iter().next() {
            return Some(task.clone());
        }
        
        // Check real-time FIFO tasks (highest priority first)
        for prio in (0..100).rev() {
            if let Some(task) = self.rt_fifo[prio].front() {
                return Some(task.clone());
            }
            if let Some(task) = self.rt_rr[prio].front() {
                return Some(task.clone());
            }
        }
        
        // Check CFS tasks (lowest vruntime first)
        if let Some(((_, tid), task)) = self.cfs_tasks.iter().next() {
            return Some(task.clone());
        }
        
        // Check batch tasks
        if let Some(task) = self.batch_queue.front() {
            return Some(task.clone());
        }
        
        // Return idle task if nothing else
        self.idle_task.clone()
    }
    
    /// Update load average
    pub fn update_load(&mut self) {
        let nr = self.nr_running.load(AtomicOrdering::Relaxed) as u64;
        let old_load = self.load_avg.load(AtomicOrdering::Relaxed);
        let new_load = (old_load * 7 + nr * 1000) / 8; // Exponential moving average
        self.load_avg.store(new_load, AtomicOrdering::Relaxed);
    }
}

/// CPU topology information
pub struct CpuTopology {
    /// Number of CPUs
    pub nr_cpus: usize,
    /// NUMA nodes
    pub numa_nodes: Vec<NumaNode>,
    /// CPU to NUMA node mapping
    pub cpu_to_node: Vec<usize>,
    /// CPU siblings (same core, different threads)
    pub cpu_siblings: Vec<Vec<usize>>,
}

/// NUMA node information
pub struct NumaNode {
    pub id: usize,
    pub cpus: Vec<usize>,
    pub memory_start: u64,
    pub memory_size: u64,
}

/// Load balancing domain
pub struct SchedDomain {
    /// Domain level (0 = SMT, 1 = MC, 2 = NUMA)
    pub level: usize,
    /// CPUs in this domain
    pub cpus: CpuSet,
    /// Balancing interval (nanoseconds)
    pub balance_interval: u64,
    /// Last balance time
    pub last_balance: AtomicU64,
    /// Imbalance threshold
    pub imbalance_threshold: f64,
}

/// Main scheduler structure
pub struct Scheduler {
    /// Per-CPU run queues
    run_queues: Vec<Mutex<RunQueue>>,
    /// All tasks in the system
    tasks: RwLock<BTreeMap<usize, Arc<Task>>>,
    /// Next task ID
    next_tid: AtomicUsize,
    /// CPU topology
    topology: CpuTopology,
    /// Scheduling domains for load balancing
    domains: Vec<SchedDomain>,
    /// System uptime (nanoseconds)
    uptime: AtomicU64,
    /// Scheduler tick counter
    tick_count: AtomicU64,
    /// Load balancing enabled
    load_balance_enabled: AtomicBool,
    /// Current CPU
    current_cpu: AtomicUsize,
}

impl Scheduler {
    pub fn new(nr_cpus: usize) -> Self {
        let mut run_queues = Vec::with_capacity(nr_cpus);
        for i in 0..nr_cpus {
            run_queues.push(Mutex::new(RunQueue::new(i)));
        }
        
        let topology = CpuTopology {
            nr_cpus,
            numa_nodes: vec![NumaNode {
                id: 0,
                cpus: (0..nr_cpus).collect(),
                memory_start: 0,
                memory_size: 0,
            }],
            cpu_to_node: vec![0; nr_cpus],
            cpu_siblings: (0..nr_cpus).map(|i| vec![i]).collect(),
        };
        
        Self {
            run_queues,
            tasks: RwLock::new(BTreeMap::new()),
            next_tid: AtomicUsize::new(1),
            topology,
            domains: Vec::new(),
            uptime: AtomicU64::new(0),
            tick_count: AtomicU64::new(0),
            load_balance_enabled: AtomicBool::new(true),
            current_cpu: AtomicUsize::new(0),
        }
    }
    
    /// Create a new task
    pub fn create_task(
        &self,
        name: String,
        policy: SchedPolicy,
        priority: Priority,
    ) -> Arc<Task> {
        let tid = self.next_tid.fetch_add(1, AtomicOrdering::Relaxed);
        let task = Arc::new(Task::new(tid, name, policy, priority));
        
        self.tasks.write().insert(tid, task.clone());
        task
    }
    
    /// Wake up a task
    pub fn wake_task(&self, task: Arc<Task>) {
        let mut state = task.state.write();
        if *state == TaskState::Waiting || *state == TaskState::New {
            *state = TaskState::Runnable;
            drop(state);
            
            // Find best CPU to run on
            let cpu = self.select_cpu(&task);
            self.run_queues[cpu].lock().enqueue(task);
        }
    }
    
    /// Select best CPU for task
    fn select_cpu(&self, task: &Arc<Task>) -> usize {
        let affinity = task.cpu_affinity.read();
        let current = self.current_cpu.load(AtomicOrdering::Relaxed);
        
        // Try current CPU first if allowed
        if affinity.is_set(current) {
            return current;
        }
        
        // Find CPU with lowest load that task can run on
        let mut best_cpu = 0;
        let mut best_load = u64::MAX;
        
        for cpu in 0..self.topology.nr_cpus {
            if !affinity.is_set(cpu) {
                continue;
            }
            
            let rq = self.run_queues[cpu].lock();
            let load = rq.load_avg.load(AtomicOrdering::Relaxed);
            if load < best_load {
                best_load = load;
                best_cpu = cpu;
            }
        }
        
        best_cpu
    }
    
    /// Main scheduling function
    pub fn schedule(&self) {
        let cpu = self.current_cpu.load(AtomicOrdering::Relaxed);
        let mut rq = self.run_queues[cpu].lock();
        
        // Save current task state if needed
        if let Some(ref current) = rq.current {
            let state = current.state.read();
            if *state == TaskState::Running {
                drop(state);
                current.state.write().clone_from(&TaskState::Runnable);
                rq.enqueue(current.clone());
            }
        }
        
        // Pick next task
        if let Some(next) = rq.pick_next() {
            // Remove from queue
            rq.dequeue(&next);
            
            // Update state
            next.state.write().clone_from(&TaskState::Running);
            
            // Update stats
            let now = self.uptime.load(AtomicOrdering::Relaxed);
            next.stats.last_scheduled.store(now, AtomicOrdering::Relaxed);
            
            // Context switch would happen here
            rq.current = Some(next);
        } else {
            // No tasks to run, idle
            rq.current = None;
        }
        
        // Update load
        rq.update_load();
    }
    
    /// Timer tick handler
    pub fn tick(&self) {
        self.tick_count.fetch_add(1, AtomicOrdering::Relaxed);
        self.uptime.fetch_add(1_000_000, AtomicOrdering::Relaxed); // 1ms tick
        
        let cpu = self.current_cpu.load(AtomicOrdering::Relaxed);
        let mut rq = self.run_queues[cpu].lock();
        
        if let Some(ref current) = rq.current {
            // Update execution time
            current.stats.exec_time.fetch_add(1_000_000, AtomicOrdering::Relaxed);
            
            // Update vruntime for CFS tasks
            if current.policy == SchedPolicy::CFS {
                let total_weight = rq.total_weight.load(AtomicOrdering::Relaxed);
                current.update_vruntime(1_000_000, total_weight);
            }
            
            // Check time slice for RR tasks
            if current.policy == SchedPolicy::RealTimeRR {
                let remaining = current.time_slice.fetch_sub(1_000_000, AtomicOrdering::Relaxed);
                if remaining <= 1_000_000 {
                    // Time slice expired, reschedule
                    current.time_slice.store(DEFAULT_TIME_SLICE, AtomicOrdering::Relaxed);
                    drop(rq);
                    self.schedule();
                    return;
                }
            }
            
            // Check deadline tasks
            if let Some(ref params) = current.deadline_params {
                let mut params = params.write();
                if params.remaining_runtime > 1_000_000 {
                    params.remaining_runtime -= 1_000_000;
                } else {
                    // Runtime exhausted, yield
                    params.remaining_runtime = 0;
                    drop(params);
                    drop(rq);
                    self.schedule();
                    return;
                }
            }
        }
        
        // Periodic load balancing
        if self.tick_count.load(AtomicOrdering::Relaxed) % 10 == 0 {
            drop(rq);
            self.load_balance();
        }
    }
    
    /// Load balancing across CPUs
    fn load_balance(&self) {
        if !self.load_balance_enabled.load(AtomicOrdering::Relaxed) {
            return;
        }
        
        let nr_cpus = self.topology.nr_cpus;
        if nr_cpus <= 1 {
            return;
        }
        
        // Calculate average load
        let mut total_load = 0u64;
        let mut loads = Vec::with_capacity(nr_cpus);
        
        for i in 0..nr_cpus {
            let rq = self.run_queues[i].lock();
            let load = rq.nr_running.load(AtomicOrdering::Relaxed) as u64;
            loads.push(load);
            total_load += load;
        }
        
        let avg_load = total_load / nr_cpus as u64;
        
        // Find busiest and idlest CPUs
        let mut busiest = 0;
        let mut busiest_load = 0;
        let mut idlest = 0;
        let mut idlest_load = u64::MAX;
        
        for (i, &load) in loads.iter().enumerate() {
            if load > busiest_load {
                busiest = i;
                busiest_load = load;
            }
            if load < idlest_load {
                idlest = i;
                idlest_load = load;
            }
        }
        
        // Check if imbalance is significant
        if busiest_load <= avg_load + 1 || busiest_load <= idlest_load + 1 {
            return;
        }
        
        // Migrate tasks from busiest to idlest
        let mut busiest_rq = self.run_queues[busiest].lock();
        let mut idlest_rq = self.run_queues[idlest].lock();
        
        // Try to migrate one CFS task
        if let Some(((vruntime, tid), task)) = busiest_rq.cfs_tasks.iter().next() {
            let task = task.clone();
            let vruntime = *vruntime;
            let tid = *tid;
            
            // Check CPU affinity
            if task.cpu_affinity.read().is_set(idlest) {
                busiest_rq.cfs_tasks.remove(&(vruntime, tid));
                busiest_rq.total_weight.fetch_sub(task.weight(), AtomicOrdering::Relaxed);
                busiest_rq.nr_running.fetch_sub(1, AtomicOrdering::Relaxed);
                
                idlest_rq.cfs_tasks.insert((vruntime, tid), task.clone());
                idlest_rq.total_weight.fetch_add(task.weight(), AtomicOrdering::Relaxed);
                idlest_rq.nr_running.fetch_add(1, AtomicOrdering::Relaxed);
                
                log::trace!("Migrated task {} from CPU {} to CPU {}", tid, busiest, idlest);
            }
        }
    }
    
    /// Set CPU affinity for task
    pub fn set_affinity(&self, task: &Arc<Task>, cpus: CpuSet) {
        let mut affinity = task.cpu_affinity.write();
        *affinity = cpus;
    }
    
    /// Get scheduler statistics
    pub fn get_stats(&self) -> SchedulerStats {
        let mut total_tasks = 0;
        let mut running_tasks = 0;
        let mut waiting_tasks = 0;
        
        for task in self.tasks.read().values() {
            total_tasks += 1;
            match *task.state.read() {
                TaskState::Running | TaskState::Runnable => running_tasks += 1,
                TaskState::Waiting => waiting_tasks += 1,
                _ => {}
            }
        }
        
        SchedulerStats {
            total_tasks,
            running_tasks,
            waiting_tasks,
            uptime: self.uptime.load(AtomicOrdering::Relaxed),
            tick_count: self.tick_count.load(AtomicOrdering::Relaxed),
        }
    }
}

/// Scheduler statistics
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    pub total_tasks: usize,
    pub running_tasks: usize,
    pub waiting_tasks: usize,
    pub uptime: u64,
    pub tick_count: u64,
}

lazy_static! {
    /// Global scheduler instance
    pub static ref SCHEDULER: RwLock<Option<Arc<Scheduler>>> = RwLock::new(None);
}

/// Initialize the scheduler
pub fn init(nr_cpus: usize) {
    let scheduler = Arc::new(Scheduler::new(nr_cpus));
    *SCHEDULER.write() = Some(scheduler);
    log::info!("Scheduler initialized with {} CPUs", nr_cpus);
}

/// Schedule on current CPU
pub fn schedule() {
    if let Some(ref scheduler) = *SCHEDULER.read() {
        scheduler.schedule();
    }
}

/// Timer tick
pub fn tick() {
    if let Some(ref scheduler) = *SCHEDULER.read() {
        scheduler.tick();
    }
}

/// Create a new task
pub fn create_task(name: String, policy: SchedPolicy, priority: Priority) -> Option<Arc<Task>> {
    SCHEDULER.read().as_ref().map(|s| s.create_task(name, policy, priority))
}

/// Wake up a task
pub fn wake_task(task: Arc<Task>) {
    if let Some(ref scheduler) = *SCHEDULER.read() {
        scheduler.wake_task(task);
    }
}

use alloc::string::String;