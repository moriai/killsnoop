use aya::{
    Bpf,
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::TracePoint,
    util::online_cpus,
};
use bytes::BytesMut;
use chrono::Local;
use std::convert::{TryFrom, TryInto};
use tokio::{signal, task};

use killsnoop_common::SignalLog;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/killsnoop"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/killsnoop"
    ))?;
    let program: &mut TracePoint = bpf.program_mut("killsnoop").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_kill")?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SignalLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let comm = data.comm.iter().map(|&s| (s as u8) as char).collect::<String>();
                    let time = Local::now().format("%H:%M:%S").to_string();
                    println!("{} PID {}({}) -> {}, SIG {}",
                        time, data.pid, comm, data.tpid, data.tsig);
                }
            }
        });
    }
    signal::ctrl_c().await.expect("failed to listen for event");

    println!("Exiting...");
    Ok(())
}
