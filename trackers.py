import subprocess, psutil, time, json, math,threading, os, random, sys
#import pandas, numpy
#import matplotlib.pyplot as plt
#import matplotlib.cm as cm

exec_memory=[]
cpu_time = 0
cpu_current_time = 0

def trackMem(popen, cputime):

	global cpu_time
	while popen.poll() is None:
		try:
			proc = psutil.Process(popen.pid)
			java_memory_usage = proc.memory_full_info().uss / 1000000
			cpu_time = proc.cpu_times().user + proc.cpu_times().system
		except psutil.NoSuchProcess:
			break
		#print(proc.cpu_times())
		#print(cpu_time)
		#print(java_memory_usage)

		if cputime:
			exec_memory.append([java_memory_usage, time.time()-current_time, cpu_time+cpu_current_time])
		else:
			exec_memory.append([java_memory_usage, time.time()-current_time])
		#print(exec_memory[-1][1])
		time.sleep(1)
	popen.wait()
	print("Process finished")



#df = pandas.read_json('data.json')
def trackRun(cmd, outname, call_time):
	exec_output = []
	global exec_memory
	global cpu_time
	exec_memory = []
	#print(call_time)
	global current_time
	current_time = call_time
	#exec_memory=[]
	popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
	print("Starting ",cmd)
	thread = threading.Thread(target=trackMem, args=[popen, False])
	thread.start()
	for line in iter(popen.stdout.readline, ""):
		#print(line)

		instant = time.time()-current_time
		try:
			cpu_time = proc.cpu_times().user + proc.cpu_times().system
			java_memory_usage = psutil.Process(popen.pid).memory_full_info().uss / 1000000
			exec_memory.append([java_memory_usage, instant, cpu_time + cpu_current_time])
			#print(java_memory_usage)
			exec_output.append([line, instant, cpu_time + cpu_current_time])
		except psutil.NoSuchProcess:
			print("\n WARNING: Process already ended\n")
			pass
			
	thread.join()
	#print("done, ", exec_memory)
	exec_output.append(["Done", time.time()-current_time, cpu_time + cpu_current_time])

	'''
	current_time=time.time()
	popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
	print("Executing memory profiling run...")
	while popen.poll() is None:
		java_memory_usage = psutil.Process(popen.pid).memory_full_info().uss / 1000000
		print(java_memory_usage)
		exec_memory.append([java_memory_usage, time.time()-current_time])
		time.sleep(1)
	popen.wait()
	'''
	#with open(outname+"_output.json", 'w', encoding='utf-8') as f:
	#    json.dump(exec_output, f, ensure_ascii=False, indent=4)
	#with open(outname+"_memory.json", 'w', encoding='utf-8') as f:
	#    json.dump(exec_memory, f, ensure_ascii=False, indent=4)
	return(exec_output, exec_memory, cpu_time)

def trackRun_cputime(cmd, outname, call_time):
	exec_output = []
	global exec_memory
	global cpu_time
	exec_memory = []
	#print(call_time)
	global current_time
	global cpu_current_time
	current_time = call_time[0]
	cpu_current_time = call_time[1]
	#exec_memory=[]
	popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
	print("Starting ", cmd, flush=True)
	thread = threading.Thread(target=trackMem, args=[popen, True])
	thread.start()

	for line in iter(popen.stdout.readline, ""):
		print(line, end="", flush=True)
		instant = time.time()-current_time
		try:
			proc = psutil.Process(popen.pid)
			cpu_time = proc.cpu_times().user + proc.cpu_times().system
			java_memory_usage = psutil.Process(popen.pid).memory_full_info().uss / 1000000
			exec_memory.append([java_memory_usage, instant, cpu_time+cpu_current_time])
			#print(java_memory_usage)
			exec_output.append([line, instant, cpu_time+cpu_current_time])
		except psutil.NoSuchProcess:
			print("\n\n WARNING!!!!!!!!!! Process already ended\n\n")
			pass
			
	thread.join()
	#print("done, ", exec_memory)
	exec_output.append(["Done", time.time()-current_time, cpu_time+cpu_current_time])

	'''
	current_time=time.time()
	popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
	print("Executing memory profiling run...")
	while popen.poll() is None:
		java_memory_usage = psutil.Process(popen.pid).memory_full_info().uss / 1000000
		print(java_memory_usage)
		exec_memory.append([java_memory_usage, time.time()-current_time])
		time.sleep(1)
	popen.wait()
	'''
	#with open(outname+"_output.json", 'w', encoding='utf-8') as f:
	#    json.dump(exec_output, f, ensure_ascii=False, indent=4)
	#with open(outname+"_memory.json", 'w', encoding='utf-8') as f:
	#    json.dump(exec_memory, f, ensure_ascii=False, indent=4)
	return(exec_output, exec_memory, cpu_time, popen.returncode)



if __name__=='__main__':
	os.environ["RAYON_NUM_THREADS"] = "1"
	run_id = os.environ.get("RUN_ID", "0")
	output_dir = "/app/measurments"
	os.makedirs(output_dir, exist_ok=True)

	cmd = [
		"/app/client",
		"server:8443",
		"server",
		"/certs/root-ca.pem",
	]

	start_time = time.time()

	out, mem, cpu_time, exit_code = trackRun_cputime(
		cmd,
		"",
		[start_time, 0]
	)

	with open(os.path.join(output_dir, f"output_client{run_id}.json"), "w", encoding="utf-8") as f:
		json.dump(out, f, ensure_ascii=False, indent=4)

	with open(os.path.join(output_dir, f"memory_client{run_id}.json"), "w", encoding="utf-8") as f:
		json.dump(mem, f, ensure_ascii=False, indent=4)

	with open(os.path.join(output_dir, f"cputime_client{run_id}.txt"), "w", encoding="utf-8") as f:
		f.write(str(cpu_time) + "\n")

	sys.exit(exit_code)
