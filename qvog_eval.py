import time

import pandas as pd

import json
import os
import re
import subprocess
import sys
from datetime import datetime
import psutil


def kill_process_tree(pid):
    parent = psutil.Process(pid)
    for child in parent.children(recursive=True):  # 获取所有子进程
        child.kill()  # 杀死子进程
    parent.kill()  # 杀死父进程


def py2graphAndQuery(cwe_list, DEBUG=True):
    start_time = time.time()
    now = datetime.now()
    formatted_now = now.strftime("%Y-%m-%d-%H-%M-%S")
    original_cwd = os.getcwd()
    output_json = f"D:\\pythonProject\\25.3.7_reposVul\\qvog_eval\\{formatted_now}.json"
    python_script_path = r'D:\【净土】\大三上学习\科研课堂\PullRequest\Python2Graph'
    local_jar_dir_path = r'D:\IdeaProjects\ResearchClassroom\QVoG-Engine\target'
    config_path = r"D:\IdeaProjects\ResearchClassroom\QVoG-Engine\target\config.json"

    for cwe_id in cwe_list:
        root = f".\\code\\cwe-{cwe_id}"
        user_list = [os.path.join(root, f) for f in os.listdir(root)]
        project_list = [os.path.abspath(os.path.join(user, os.listdir(user)[0])) for user in user_list]

        for project in project_list:
            print("===== processing cwe: {}, file: {} =====".format(cwe_id, project))

            python_command = [
                "D:\\Python3.9.7\\python.exe", "D:/【净土】/大三上学习/科研课堂/PullRequest/Python2Graph/src/py2graph.py",
                "--build", "--force", "-p", project,
                "--calc-thread=1", "--io-thread=8", "--v-batch=400", "--e-batch=200"
            ]
            try:
                os.chdir(python_script_path)
                result = subprocess.run(python_command)
                if result.stderr:
                    print("Standard Error from python execution:")
                    print(result.stderr)
            except subprocess.CalledProcessError as e:
                print(f"An error occurred while executing the python file: {e}")
                sys.exit(1)
            finally:
                os.chdir(original_cwd)

            print("===== python2graph completed cwe: {}, file: {} =====".format(cwe_id, project))

            try:
                with open(config_path, 'r') as config_file:
                    config = json.load(config_file)
                config["llm"]["cwe"] = f"cwe-{cwe_id}"
                config["llm"]["path"] = project
                with open(config_path, 'w') as config_file:
                    json.dump(config, config_file, indent=2)

                os.chdir(local_jar_dir_path)  # 切换到目标目录

                jar_command = [
                    'java', '-jar', 'QVoGine-1.0.jar',
                    '--language', 'python',
                    '--query', 'LLM.LLMQuery',
                    '--style', 'json'
                ]

                with open(output_json, 'a') as outfile:
                    outfile.write(f"\ncwe: {cwe_id}\nfile: {project}\n")
                    outfile.flush()

                    timeout = 300
                    # 使用Popen代替run，以便更好地控制子进程
                    process = subprocess.Popen(jar_command, stdout=outfile, stderr=subprocess.PIPE, text=True)

                    try:
                        # 等待指定的秒数让子进程完成
                        process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        print(f"Process exceeded the time limit of {timeout} seconds. Terminating...")
                        try:
                            kill_process_tree(process.pid)
                        except psutil.NoSuchProcess:
                            print("No such process found.")
                        except Exception as e:
                            print(f"Failed to kill process: {e}")

                    # 检查是否有stderr输出
                    if process.stderr:
                        stderr_output = process.stderr.read()
                        if stderr_output:
                            print("Standard Error from .jar execution:")
                            print(stderr_output)
            except subprocess.CalledProcessError as e:
                print(f"An error occurred while executing the .jar file: {e}")
                sys.exit(1)
            finally:
                os.chdir(original_cwd)

            print("===== QVoG query completed cwe: {}, file: {} =====".format(cwe_id, project))

            if DEBUG:
                return

    end_time = time.time()
    with open(output_json, 'a') as outfile:
        outfile.write(f"\nTotal execution time: {end_time - start_time} seconds")



def analysis(cwe_list, json_file_path):
    with open(json_file_path, 'r') as f:
        # content = f.read()
        lines = f.readlines()
    # content = re.sub(r'```json(.*?)```', '', content, flags=re.DOTALL)
    # lines = content.split("\n")
    pred_results = []

    while lines:
        if "cwe:" in lines[0]:
            cwe = lines.pop(0).split("cwe: ")[1].strip()
            file_path = lines.pop(0).split("file: ")[1].strip()
            pred_result = {
                'cwe': cwe,
                'file': file_path,
            }

            # 找到 JSON 开始的位置
            json_start_index = None
            for i, line in enumerate(lines):
                if line.strip().startswith("{") and line.strip().endswith("}"):
                    json_start_index = i
                    break

            pred_result['json_detail'] = json.loads(lines[json_start_index])
            del lines[:json_start_index + 1]

            json_start_index = None
            for i, line in enumerate(lines):
                if line.strip().startswith("{"):
                    json_start_index = i
                    break

            if json_start_index is not None:
                json_lines = []
                brace_count = 0
                for line in lines[json_start_index:]:
                    json_lines.append(line)
                    brace_count += line.count('{') - line.count('}')
                    if brace_count == 0:
                        break

                json_str = "\n".join(json_lines)

                try:
                    if json_str.find("headers") > 0:
                        json_data = json.loads(json_str)
                        pred_result['json'] = json_data
                        pred_results.append(pred_result)
                except json.JSONDecodeError as e:
                    print(f"Failed to parse JSON: {e}")

                # 移除已处理的行
                del lines[:json_start_index + len(json_lines)]
        else:
            lines.pop(0)


    root = dict()
    for cwe in cwe_list:
        root[f"cwe-{cwe}"] = {}
        ground_truth_df = pd.read_csv(f"ground_truth_cwe_{cwe}.csv")
        for index, row in ground_truth_df.iterrows():
            source_path = row['source_path']
            file_path = os.path.join(os.getcwd(), "code", f"cwe-{cwe}", source_path.split('/')[2], source_path.split('/')[3])
            source_path_rel = '\\'.join(row['source_path'].split('/')[4:])
            sink_path_rel = '\\'.join(row['sink_path'].split('/')[4:])
            barrier_path_rel = '\\'.join(row['barrier_path'].split('/')[4:])

            if not root[f"cwe-{cwe}"].get(file_path):
                root[f"cwe-{cwe}"][file_path] = {
                    'real_pair': [],
                    'real_source': [],
                    'real_sink': [],
                    'real_barrier': [],
                    'pred_source': [],
                    'pred_sink': [],
                    'pred_barrier': [],
                    'pred_pair': [],
                }
            root[f"cwe-{cwe}"][file_path]['real_source'].append(f"{source_path_rel}:{row['source_line']}")
            if not row['sink_line'].startswith('['):
                root[f"cwe-{cwe}"][file_path]['real_sink'].append(f"{sink_path_rel}:{row['sink_line']}")
                if row['security'] == 0:
                    root[f"cwe-{cwe}"][file_path]['real_pair'].append([f"{source_path_rel}:{row['source_line']}", f"{sink_path_rel}:{row['sink_line']}"])
            else:
                if row['security'] == 0:
                    for sink_line in row['sink_line'][1: -1].split(','):
                        root[f"cwe-{cwe}"][file_path]['real_sink'].append(f"{sink_path_rel}:{row['sink_line']}")
                        root[f"cwe-{cwe}"][file_path]['real_pair'].append([f"{source_path_rel}:{row['source_line']}", f"{sink_path_rel}:{sink_line}"])
            if row['security'] == 1:
                if not str(row['barrier_line']).startswith('['):
                    root[f"cwe-{cwe}"][file_path]['real_barrier'].append(f"{barrier_path_rel}:{round(int(row['barrier_line']))}")
                else:
                    for barrier_line in row['barrier_line'][1: -1].split(','):
                        root[f"cwe-{cwe}"][file_path]['real_barrier'].append(f"{barrier_path_rel}:{round(int(barrier_line))}")


        for result in pred_results:
            cwe = result['cwe']
            file_path = result['file']
            json_data = result['json']
            json_detail = result['json_detail']

            root[f"cwe-{cwe}"][file_path]['pred_source'] = json_detail['pred_source']
            root[f"cwe-{cwe}"][file_path]['pred_sink'] = json_detail['pred_sink']
            root[f"cwe-{cwe}"][file_path]['pred_barrier'] = json_detail['pred_barrier']
            for row in json_data['rows']:
                source_path_rel = row[0][1: row[0].find(')')]
                sink_path_rel = row[1][1: row[1].find(')')]
                for pair in root[f"cwe-{cwe}"][file_path]['pred_pair']:
                    if pair[0] == source_path_rel and pair[1] == sink_path_rel:
                        break
                else:
                    root[f"cwe-{cwe}"][file_path]['pred_pair'].append([source_path_rel, sink_path_rel])

        pair_cal = [0, 0, 0]
        source_cal = [0, 0, 0]
        sink_cal = [0, 0, 0]
        barrier_cal = [0, 0, 0]
        for file_path, file_obj in root[f"cwe-{cwe}"].items():
            cross = 0
            for pair in file_obj['pred_pair']:
                for real_pair in file_obj['real_pair']:
                    if pair[0] == real_pair[0] and pair[1] == real_pair[1]:
                        cross += 1
            # print(f"cwe-{cwe}, {file_path}, cross = {cross}")
            pair_cal[0] += len(file_obj['real_pair']) - cross
            pair_cal[1] += cross
            pair_cal[2] += len(file_obj['pred_pair']) - cross

            cross = 0
            for source in file_obj['pred_source']:
                for real_source in file_obj['real_source']:
                    if source == real_source:
                        cross += 1
                        break
            source_cal[0] += len(file_obj['real_source']) - cross
            source_cal[1] += cross
            source_cal[2] += len(file_obj['pred_source']) - cross

            cross = 0
            for sink in file_obj['pred_sink']:
                for real_sink in file_obj['real_sink']:
                    if sink == real_sink:
                        cross += 1
                        break
            sink_cal[0] += len(file_obj['real_sink']) - cross
            sink_cal[1] += cross
            sink_cal[2] += len(file_obj['pred_sink']) - cross

            cross = 0
            for barrier in file_obj['pred_barrier']:
                for real_barrier in file_obj['real_barrier']:
                    if barrier == real_barrier:
                        cross += 1
                        break
            barrier_cal[0] += len(file_obj['real_barrier']) - cross
            barrier_cal[1] += cross
            barrier_cal[2] += len(file_obj['pred_barrier']) - cross

        print(f"cwe-{cwe}\npair_cal = {pair_cal}\nsource_cal = {source_cal}")
        print(f"sink_cal = {sink_cal}\nbarrier_cal = {barrier_cal}")
        with open("result.json", 'w') as f:
            json.dump(root, f, indent=4)


if __name__ == '__main__':
    cwe_list = [22]
    # py2graphAndQuery(cwe_list, False)
    analysis(cwe_list, "qvog_eval\\2025-04-13-18-30-01.json")
