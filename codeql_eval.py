import os
import json
import ast
import re
import subprocess
from subprocess import TimeoutExpired
import pandas as pd

language_table = {
    "pip": "python",
    "maven": "java"
}



def createDatabase():
    language_dir = "python"
    database_path = os.path.join("database")
    if not os.path.exists(database_path):
        os.mkdir(database_path)
    cwe_dirs = os.listdir(os.path.join('.', 'code'))
    for cwe_dir in cwe_dirs:
        if not os.path.exists(os.path.join('.', 'database', cwe_dir)):
            os.mkdir(os.path.join('.', 'database', cwe_dir))

        project_dirs = os.listdir(os.path.join('.', 'code', cwe_dir))
        for project_dir in project_dirs:
            project_path = os.path.join('.', 'code', cwe_dir, project_dir)
            target_path = os.path.join('.', 'database', cwe_dir, project_dir)
            if not os.path.exists(target_path):
                print("===== creating database " + project_dir + " =====")
                os.system("codeql database create --language={} {} --source-root {}".format(language_dir, target_path, project_path))


def cweConvert(cwe):
    num = cwe[cwe.find('-') + 1:]
    if len(num) < 3:
        return 'CWE-0' + num
    else:
        return 'CWE-' + num


def analyzeDatabase():
    language_dir = "python"
    ql_root_path = r"D:\【净土】\大三上学习\科研课堂\codeql_master_python_ql_src_Security_\codeql_test\vscode-codeql-starter\ql\python\ql\src\Security"
    database_path = os.path.join("sarif")
    if not os.path.exists(database_path):
        os.mkdir(database_path)
    cwe_dirs = os.listdir(os.path.join('.', 'database'))
    for cwe_dir in cwe_dirs:
        if not os.path.exists(os.path.join('.', 'sarif', cwe_dir)):
            os.mkdir(os.path.join('.', 'sarif', cwe_dir))

        project_dirs = os.listdir(os.path.join('.', 'database', cwe_dir))
        for project_dir in project_dirs:
            project_path = os.path.join('.', 'database', cwe_dir, project_dir)
            ql_cwe_dir = cweConvert(cwe_dir)
            for root, dirs, files in os.walk(str(os.path.join(ql_root_path, ql_cwe_dir)), topdown=True):
                for file in files:
                    if file.endswith(".ql"):
                        ql_path = os.path.join(root, file)
                        target_dir = os.path.join('.', 'sarif', cwe_dir, project_dir)
                        if not os.path.exists(target_dir):
                            os.mkdir(target_dir)
                        target_path = os.path.join('.', 'sarif', cwe_dir, project_dir, file[: file.find('.ql')])
                        if not os.path.exists(target_path):
                            print("===== analyzing database " + project_dir + " using " + file + " =====")
                            os.system(
                                "codeql database analyze {} {} --format=sarif-latest --output={}.sarif".format(project_path, ql_path,
                                                                                                                   target_path))


def judgeSource(statement):
    while statement.endswith("\\") or statement.endswith(",") or statement.endswith("\n"):
        statement = statement[:-1]
        statement = statement.rstrip(" ")
    # print(statement)
    try:
        parsed_ast = ast.parse(statement)
    except SyntaxError:
        return True
    for node in ast.walk(parsed_ast):
        if isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
            return False

    return True


def getCodeLine(root, uri, lineno, end_line=None):
    path = os.path.join(root.replace('sarif', 'code', 1), uri)
    with open(path, 'r', encoding='utf-8') as src_code:
        lines = src_code.readlines()
    if end_line is None:
        return lines[lineno]
    else:
        return lines[lineno: end_line + 1]


def getCode(root, location, sink_line):
    uri = location['location']['physicalLocation']["artifactLocation"]['uri']
    lineno = location['location']['physicalLocation']['region']['startLine'] - 1
    while True:
        line = getCodeLine(root, uri, lineno)
        if re.match(r"^.*def +\w+\(.*$", line) or lineno < 0:
            break
        lineno -= 1
    lines = getCodeLine(root, uri, lineno, sink_line);
    if len(lines) < 100:
        return ''.join(lines)
    else:
        return ''


def copyFile(src, target):
    if not os.path.exists(target):
        if not os.path.exists(os.path.dirname(target)):
            os.makedirs(os.path.dirname(target))
        with open(src, 'r', encoding='utf-8') as src_file:
            with open(target, 'w', encoding='utf-8') as target_file:
                target_file.write(src_file.read())


def getDataItem(language, root, thread_flow):
    try:
        locations = thread_flow['locations']
        source_obj = {}
        source_code_line = None
        begin_index = 0
        for index, location in enumerate(locations):
            source_code_line = getCodeLine(root, location['location']['physicalLocation']["artifactLocation"]['uri'],
                                           location['location']['physicalLocation']['region']['startLine'] - 1)
            if judgeSource(source_code_line):
                source_obj = location
                begin_index = index
                break
        if source_obj == {}:
            return None
        sink_obj = locations[len(locations) - 1]

        taint_arr = []
        for i in range(begin_index, len(locations)):
            taint_arr.append(str(locations[i]['location']['physicalLocation']['region']['startLine'] - 1))

        source_path = os.path.join(root.replace('sarif', 'file', 1), source_obj['location']['physicalLocation']["artifactLocation"]['uri'])
        sink_path = os.path.join(root.replace('sarif', 'file', 1), sink_obj['location']['physicalLocation']["artifactLocation"]['uri'])
        copyFile(source_path.replace('file', 'code', 1), source_path)
        copyFile(sink_path.replace('file', 'code', 1), sink_path)
        result = {
            "index": "cwe-" + re.search(r'cwe-(\d+)', root).group(1),
            "language": language,
            # "code": getCode(root, source_obj, sink_obj['location']['physicalLocation']['region']['startLine'] - 1),
            "source_code": source_code_line.strip(),
            "source_line": source_obj['location']['physicalLocation']['region']['startLine'] - 1,
            "sink_code": (getCodeLine(root, sink_obj['location']['physicalLocation']["artifactLocation"]['uri'],
                                      sink_obj['location']['physicalLocation']['region']['startLine'] - 1)).strip(),
            "sink_line": sink_obj['location']['physicalLocation']['region']['startLine'] - 1,
            "source_path": source_path,
            "sink_path": sink_path,
            "taint_path": "->".join(taint_arr),
            "hit": 0
        }
        print(result)
        return result
    except Exception as e:
        print(e)
        return None


def generateData():
    data_items = []
    language_dir = "python"
    for root, dirs, files in os.walk(os.path.join('.', 'sarif'), topdown=True):
        for file in files:
            if file.endswith(".sarif"):
                path = os.path.join(root, file)
                with open(path, encoding='utf-8') as f:
                    sarif = json.load(f)
                # print(path + ": ", len(sarif['runs'][0]['results']))
                if str(sarif).count("codeFlows") != 0:
                    results = sarif['runs'][0]['results']
                    for result in results:
                        if 'codeFlows' in result:
                            code_flows = result['codeFlows']
                            for code_flow in code_flows:
                                if 'threadFlows' in code_flow:
                                    thread_flows = code_flow['threadFlows']
                                    for thread_flow in thread_flows: # generally: len(thread_flows) == 1
                                        data_item = getDataItem(language_dir, root, thread_flow)
                                        if data_item is not None:
                                            data_items.append(data_item)
    return data_items


def outputData(data_items):
    data = {}
    for key in data_items[0]:
        data[key] = []
    for data_item in data_items:
        for key in data_item:
            data[key].append(data_item[key])
    df = pd.DataFrame(data)
    df = df.drop_duplicates(subset=["source_code", 'sink_code'])
    df.to_csv('codeql_output.csv', index=False)


if __name__ == "__main__":
    # createDatabase()
    # analyzeDatabase()
    data_items = generateData()
    outputData(data_items)
