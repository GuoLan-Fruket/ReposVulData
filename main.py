import json
import pandas as pd
import os

path = r'D:\【净土】\大三上学习\科研课堂\数据\reposVul\ReposVul_python.jsonl'

def filter():
    cwe = 601
    with open(path, 'r', encoding='utf-8') as f:
        df = pd.read_csv(f'json/cwe-{cwe}.csv')
        visited = set(df['cve_id'])
        while True:
            line = f.readline()
            if not line:
                break
            data = json.loads(line)
            if f'CWE-{cwe}' in data['cwe_id']:
                if data['cve_id'] in visited:
                    continue
                print('=' * 50)
                print(data['cve_id'], end=',')
                print(data["html_url"], end=',\n')
                with open(f'json/cwe-{cwe}/{data["cve_id"]}.json', 'w') as json_file:
                    json_file.write(line)
                msg = input()
                if msg == 'q':
                    break


def calculate():
    cwe_map = {}
    with open(path, 'r', encoding='utf-8') as f:
        while True:
            line = f.readline()
            if not line:
                break
            data = json.loads(line)
            cwe_id_list = data['cwe_id']
            for cwe_id in cwe_id_list:
                if cwe_id not in cwe_map:
                    cwe_map[cwe_id] = 1
                else:
                    cwe_map[cwe_id] += 1
    # cwe_map按照值降序排序
    cwe_map = sorted(cwe_map.items(), key=lambda x: x[1], reverse=True)
    for cwe_id, count in cwe_map:
        print(f'{cwe_id}: {count}')


def data(write_file=False):
    cwe_list = [22, 74, 78, 79, 94]
    for cwe_id in cwe_list:
        df = pd.read_csv(f'json/cwe-{cwe_id}.csv')
        try:
            df_gt = pd.read_csv(f'ground_truth_cwe_{cwe_id}.csv')
        except FileNotFoundError:
            df_gt = pd.DataFrame()
        # index, language, cve_id, commit, source_path, sink_path, barrier_path, source_line, sink_line,
        # barrier_line, source_code, sink_code,barrier_code, is_vulnerability
        new_data = {
            'index': [],
            'language': [],
            'cve_id': [],
            'commit': [],
            'source_path': [],
            'sink_path': [],
            'barrier_path': [],
            'source_line': [],
            'sink_line': [],
            'barrier_line': [],
            'source_code': [],
            'sink_code': [],
            'barrier_code': [],
            'is_vulnerability': []
        }
        for index, row in df.iterrows():
            if pd.isna(row['commit_url']):
                continue
            file_list = []
            if row['file'].startswith('['):
                row_file = row['file'][1:-1].split(',')
                for file in row_file:
                    file_list.append(file.strip())
            else:
                file_list.append(row['file'])
            with open(f'json/cwe-{cwe_id}/{row["cve_id"]}.json', 'r', encoding='utf-8') as json_f:
                json_data = json.loads(json_f.readline())
                owner, repo = json_data['html_url'].split('/')[3:5]
                for file in file_list:
                    file_path = f'code/cwe-{cwe_id}/{owner}/{repo}/{file}'
                    file_dir = os.path.dirname(file_path)
                    if not os.path.exists(file_dir):
                        os.makedirs(file_dir)
                    for detail in json_data['details']:
                        if detail['file_name'] == file:
                            point = file_path.rfind(".py")
                            if point == -1:
                                assert "Not Python File"
                            file_path_before = file_path[:point] + "_before.py"
                            if write_file:
                                with open(file_path, 'w', encoding='utf-8') as f:
                                    f.write(detail['code'])
                                with open(file_path_before, 'w', encoding='utf-8') as f:
                                    f.write(detail['code_before'])
                            new_data['index'] += [f'cwe-{cwe_id}', f'cwe-{cwe_id}']
                            new_data['language'] += ['python', 'python']
                            new_data['cve_id']+= [row['cve_id'], row['cve_id']]
                            new_data['commit'] += [json_data['html_url'].split('/')[6], json_data['html_url'].split('/')[6]]
                            new_data['source_path'] += [file_path, file_path_before]
                            new_data['sink_path'] += [file_path, file_path_before]
                            new_data['barrier_path'] += [file_path, file_path_before]
                            new_data['source_line'] += [None, None]
                            new_data['sink_line'] += [None, None]
                            new_data['barrier_line'] += [None, None]
                            new_data['source_code'] += [None, None]
                            new_data['sink_code'] += [None, None]
                            new_data['barrier_code'] += [None, None]
                            new_data['is_vulnerability'] += [1, 0]
                            break
        new_df = pd.DataFrame(new_data)
        df_gt = pd.concat([df_gt, new_df], ignore_index=True)
        df_gt.to_csv(f'ground_truth_cwe_{cwe_id}.csv', index=False, encoding='utf-8')


if __name__ == '__main__':
    # filter()
    # calculate()
    data(True)