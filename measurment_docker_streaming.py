import csv
import time
import threading
import docker
import sys

CONTAINERS = ["work1_dfs", "work2_dfs", "work3_dfs", "coord_dfs"]


def cpu_percent(stats):
    cpu_stats = stats.get("cpu_stats", {})
    precpu_stats = stats.get("precpu_stats", {})

    cpu_total = cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
    precpu_total = precpu_stats.get("cpu_usage", {}).get("total_usage", 0)

    system_total = cpu_stats.get("system_cpu_usage", 0)
    presystem_total = precpu_stats.get("system_cpu_usage", 0)

    cpu_delta = cpu_total - precpu_total
    system_delta = system_total - presystem_total

    online_cpus = cpu_stats.get("online_cpus")
    if online_cpus is None:
        percpu = cpu_stats.get("cpu_usage", {}).get("percpu_usage", []) or [0]
        online_cpus = max(len(percpu), 1)

    if cpu_delta > 0 and system_delta > 0:
        return (cpu_delta / system_delta) * online_cpus * 100.0
    return 0.0


def memory_values(stats):
    mem = stats.get("memory_stats", {})
    usage = mem.get("usage", 0)
    limit = mem.get("limit", 0)
    st = mem.get("stats", {})

    cache = st.get("inactive_file")
    if cache is None:
        cache = st.get("total_inactive_file", 0)

    workingset = max(usage - cache, 0)
    return usage, workingset, limit


def reader_worker(container_name, t0, iteration):
    client = docker.APIClient(version="auto", timeout=30)
    filename = f"metrics_{container_name}_{iteration}.csv"
    sample_idx = 0
    stream = None

    try:
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "elapsed_s",
                "container_name",
                "sample_idx",
                "cpu_percent",
                "mem_usage_bytes_raw",
                "mem_usage_bytes_workingset",
                "mem_limit_bytes",
            ])

            stream = client.stats(container_name, stream=True, decode=True)

            for stats in stream:
                elapsed_s = time.perf_counter() - t0
                cpu = cpu_percent(stats)
                mem_raw, mem_ws, mem_limit = memory_values(stats)

                writer.writerow([
                    round(elapsed_s, 6),
                    container_name,
                    sample_idx,
                    round(cpu, 4),
                    mem_raw,
                    mem_ws,
                    mem_limit,
                ])
                f.flush()
                sample_idx += 1

    except Exception as e:
        print(f"[{container_name}] error: {e}")

    finally:
        close_fn = getattr(stream, "close", None)
        if callable(close_fn):
            try:
                close_fn()
            except Exception:
                pass
        try:
            client.close()
        except Exception:
            pass


def main(iteration):
    t0 = time.perf_counter()
    threads = []

    for name in CONTAINERS:
        t = threading.Thread(
            target=reader_worker,
            args=(name, t0, iteration),
            name=name,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 measurement_docker_streaming.py <iteration>")
        sys.exit(1)

    iteration = int(sys.argv[1])
    main(iteration)