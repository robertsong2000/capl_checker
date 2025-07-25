#!/usr/bin/env python3
"""
CAPL Static Syntax Checker
A static analysis tool for CAN Access Programming Language (CAPL) files
Similar to cppcheck for C/C++ code
"""

import re
import os
import sys
import argparse
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    STYLE = "style"


@dataclass
class Issue:
    file_path: str
    line_number: int
    column: int
    severity: Severity
    message: str
    rule_id: str


class CAPLChecker:
    def __init__(self):
        self.issues: List[Issue] = []
        self.variables: Dict[str, str] = {}  # variable_name -> type
        self.functions: Dict[str, Dict] = {}  # function_name -> {return_type, params}
        self.current_file = ""
        self.current_line = 0
        
        # CAPL keywords
        self.keywords = {
            'variables', 'on', 'message', 'signal', 'timer', 'key', 'start',
            'preStart', 'stopMeasurement', 'int', 'long', 'float', 'double',
            'char', 'byte', 'word', 'dword', 'qword', 'if', 'else', 'while',
            'for', 'do', 'switch', 'case', 'default', 'break', 'continue',
            'return', 'void', 'this', 'output', 'write', 'writeToLog',
            'getValue', 'putValue', 'setSignal', 'getSignal', 'canDatabase',
            'testWaitForSignalMatch', 'testStepPass', 'testStepFail'
        }
        
        # Built-in functions
        self.builtin_functions = {
            'write', 'writeToLog', 'getValue', 'putValue', 'setSignal',
            'getSignal', 'output', 'random', 'abs', 'min', 'max', 'strlen',
            'strstr', 'substr', 'sprintf', 'snprintf', 'atoi', 'atof',
            'testWaitForSignalMatch', 'testStepPass', 'testStepFail',
            'setTimer', 'cancelTimer', 'isTimerActive'
        }

    def check_file(self, file_path: str) -> List[Issue]:
        """检查单个CAPL文件"""
        self.current_file = file_path
        self.issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except UnicodeDecodeError:
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    lines = f.readlines()
            except Exception as e:
                self.add_issue(1, 0, Severity.ERROR, f"Cannot read file: {e}", "file-read-error")
                return self.issues
        except Exception as e:
            self.add_issue(1, 0, Severity.ERROR, f"Cannot read file: {e}", "file-read-error")
            return self.issues
        
        # 预处理：移除注释
        processed_lines = self._remove_comments(lines)
        
        # 各种检查
        for i, line in enumerate(processed_lines, 1):
            self.current_line = i
            self._check_line_length(line, i)
            self._check_trailing_whitespace(line, i)
            self._check_syntax_errors(line, i)
            self._check_variable_declaration(line, i)
            self._check_function_declaration(line, i)
            self._check_undefined_variables(line, i)
            self._check_unused_variables(processed_lines, i)
            self._check_magic_numbers(line, i)
            self._check_naming_conventions(line, i)
            self._check_capl_specific_issues(line, i)
        
        # 全局检查
        self._check_global_issues(processed_lines)
        
        return self.issues

    def _remove_comments(self, lines: List[str]) -> List[str]:
        """移除注释"""
        processed = []
        in_block_comment = False
        
        for line in lines:
            new_line = ""
            i = 0
            while i < len(line):
                if not in_block_comment:
                    if i < len(line) - 1 and line[i:i+2] == '//':
                        # 单行注释
                        break
                    elif i < len(line) - 1 and line[i:i+2] == '/*':
                        # 块注释开始
                        in_block_comment = True
                        i += 2
                        continue
                    else:
                        new_line += line[i]
                else:
                    if i < len(line) - 1 and line[i:i+2] == '*/':
                        # 块注释结束
                        in_block_comment = False
                        i += 2
                        continue
                i += 1
            
            processed.append(new_line)
        
        return processed

    def _check_line_length(self, line: str, line_num: int):
        """检查行长度"""
        if len(line.rstrip()) > 120:
            self.add_issue(line_num, len(line.rstrip()), Severity.STYLE,
                          "Line too long (>120 characters)", "line-too-long")

    def _check_trailing_whitespace(self, line: str, line_num: int):
        """检查行尾空白"""
        if line.rstrip() != line.rstrip('\n').rstrip('\r'):
            self.add_issue(line_num, len(line.rstrip()), Severity.STYLE,
                          "Trailing whitespace", "trailing-whitespace")

    def _check_syntax_errors(self, line: str, line_num: int):
        """检查基本语法错误"""
        stripped = line.strip()
        
        # 检查括号匹配
        open_parens = stripped.count('(')
        close_parens = stripped.count(')')
        if open_parens != close_parens:
            self.add_issue(line_num, 0, Severity.ERROR,
                          "Mismatched parentheses", "mismatched-parentheses")
        
        # 检查大括号匹配
        open_braces = stripped.count('{')
        close_braces = stripped.count('}')
        if open_braces != close_braces:
            self.add_issue(line_num, 0, Severity.ERROR,
                          "Mismatched braces", "mismatched-braces")
        
        # 检查分号
        if (stripped and not stripped.endswith((';', '{', '}', ':', '\\')) 
            and not stripped.startswith(('#', 'on ', 'variables', 'includes'))
            and not any(keyword in stripped for keyword in ['if', 'else', 'while', 'for', 'do', 'switch', 'case'])):
            if not re.match(r'^\s*(//|/\*|\*)', stripped):
                self.add_issue(line_num, len(stripped), Severity.WARNING,
                              "Missing semicolon", "missing-semicolon")

    def _check_variable_declaration(self, line: str, line_num: int):
        """检查变量声明"""
        # CAPL变量声明模式
        var_pattern = r'\b(int|long|float|double|char|byte|word|dword|qword)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.finditer(var_pattern, line)
        
        for match in matches:
            var_type = match.group(1)
            var_name = match.group(2)
            
            # 检查变量名是否已存在
            if var_name in self.variables:
                self.add_issue(line_num, match.start(2), Severity.WARNING,
                              f"Variable '{var_name}' redeclared", "variable-redeclared")
            else:
                self.variables[var_name] = var_type
            
            # 检查变量名命名规范
            if not re.match(r'^[a-z][a-zA-Z0-9_]*$', var_name):
                self.add_issue(line_num, match.start(2), Severity.STYLE,
                              f"Variable '{var_name}' should use camelCase", "naming-convention")

    def _check_function_declaration(self, line: str, line_num: int):
        """检查函数声明"""
        # CAPL函数声明模式
        func_pattern = r'\b(void|int|long|float|double|char)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        match = re.search(func_pattern, line)
        
        if match:
            return_type = match.group(1)
            func_name = match.group(2)
            
            # 检查函数名是否已存在
            if func_name in self.functions:
                self.add_issue(line_num, match.start(2), Severity.WARNING,
                              f"Function '{func_name}' redeclared", "function-redeclared")
            else:
                self.functions[func_name] = {'return_type': return_type, 'line': line_num}

    def _check_undefined_variables(self, line: str, line_num: int):
        """检查未定义的变量"""
        # 查找变量使用
        var_usage_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        matches = re.finditer(var_usage_pattern, line)
        
        for match in matches:
            var_name = match.group(1)
            
            # 跳过关键字和内置函数
            if (var_name in self.keywords or 
                var_name in self.builtin_functions or
                var_name in ['true', 'false', 'NULL']):
                continue
            
            # 检查是否在变量声明行
            if re.search(r'\b(int|long|float|double|char|byte|word|dword|qword)\s+' + var_name, line):
                continue
            
            # 检查是否在函数声明行
            if re.search(r'\b(void|int|long|float|double|char)\s+' + var_name + r'\s*\(', line):
                continue
            
            # 检查变量是否已声明
            if (var_name not in self.variables and 
                var_name not in self.functions and
                not var_name.isdigit()):
                self.add_issue(line_num, match.start(1), Severity.WARNING,
                              f"Undefined variable '{var_name}'", "undefined-variable")

    def _check_unused_variables(self, lines: List[str], line_num: int):
        """检查未使用的变量（简化版）"""
        # 这里只做基本检查，实际实现需要更复杂的数据流分析
        pass

    def _check_magic_numbers(self, line: str, line_num: int):
        """检查魔法数字"""
        # 查找数字常量（排除0, 1, -1）
        number_pattern = r'\b(?<![\w.])((?:[2-9]|[1-9]\d+)(?:\.\d+)?)\b(?![\w.])'
        matches = re.finditer(number_pattern, line)
        
        for match in matches:
            number = match.group(1)
            # 排除一些常见的非魔法数字
            if number not in ['2', '10', '100', '1000']:
                self.add_issue(line_num, match.start(1), Severity.INFO,
                              f"Magic number '{number}' should be replaced with named constant",
                              "magic-number")

    def _check_naming_conventions(self, line: str, line_num: int):
        """检查命名规范"""
        # 检查常量命名（应该全大写）
        const_pattern = r'\b(const\s+\w+\s+)([a-zA-Z_][a-zA-Z0-9_]*)'
        match = re.search(const_pattern, line)
        if match:
            const_name = match.group(2)
            if not const_name.isupper():
                self.add_issue(line_num, match.start(2), Severity.STYLE,
                              f"Constant '{const_name}' should be UPPER_CASE", "naming-convention")

    def _check_capl_specific_issues(self, line: str, line_num: int):
        """检查CAPL特定的问题"""
        # 检查on message事件处理
        if re.search(r'\bon\s+message\s+\w+', line):
            if not re.search(r'\{', line) and not any('{' in next_line for next_line in [line]):
                self.add_issue(line_num, 0, Severity.WARNING,
                              "on message handler should have implementation", "empty-message-handler")
        
        # 检查timer使用
        if 'setTimer' in line:
            if not re.search(r'setTimer\s*\(\s*\w+\s*,\s*\d+\s*\)', line):
                self.add_issue(line_num, line.find('setTimer'), Severity.WARNING,
                              "setTimer should have timer name and duration", "invalid-timer-usage")
        
        # 检查signal访问
        if re.search(r'\$\w+', line):
            signal_match = re.search(r'\$(\w+)', line)
            if signal_match:
                signal_name = signal_match.group(1)
                # 这里可以添加信号名称验证逻辑
                pass

    def _check_global_issues(self, lines: List[str]):
        """检查全局问题"""
        content = '\n'.join(lines)
        
        # 检查是否有variables块
        if 'variables' not in content:
            self.add_issue(1, 0, Severity.INFO,
                          "No variables block found", "no-variables-block")
        
        # 检查是否有on start事件
        if 'on start' not in content and 'on preStart' not in content:
            self.add_issue(1, 0, Severity.INFO,
                          "No startup event handler found", "no-startup-handler")

    def add_issue(self, line_num: int, column: int, severity: Severity, message: str, rule_id: str):
        """添加问题到列表"""
        issue = Issue(
            file_path=self.current_file,
            line_number=line_num,
            column=column,
            severity=severity,
            message=message,
            rule_id=rule_id
        )
        self.issues.append(issue)

    def format_issues(self, format_type: str = "text") -> str:
        """格式化输出问题"""
        if format_type == "xml":
            return self._format_xml()
        elif format_type == "json":
            return self._format_json()
        else:
            return self._format_text()

    def _format_text(self) -> str:
        """文本格式输出"""
        if not self.issues:
            return "No issues found.\n"
        
        output = []
        for issue in sorted(self.issues, key=lambda x: (x.file_path, x.line_number)):
            output.append(f"{issue.file_path}:{issue.line_number}:{issue.column}: "
                         f"{issue.severity.value}: {issue.message} [{issue.rule_id}]")
        
        # 统计信息
        error_count = sum(1 for issue in self.issues if issue.severity == Severity.ERROR)
        warning_count = sum(1 for issue in self.issues if issue.severity == Severity.WARNING)
        info_count = sum(1 for issue in self.issues if issue.severity == Severity.INFO)
        style_count = sum(1 for issue in self.issues if issue.severity == Severity.STYLE)
        
        output.append(f"\nSummary: {error_count} errors, {warning_count} warnings, "
                     f"{info_count} info, {style_count} style issues")
        
        return '\n'.join(output) + '\n'

    def _format_xml(self) -> str:
        """XML格式输出"""
        output = ['<?xml version="1.0" encoding="UTF-8"?>', '<results>']
        
        for issue in self.issues:
            output.append(f'  <error file="{issue.file_path}" line="{issue.line_number}" '
                         f'column="{issue.column}" severity="{issue.severity.value}" '
                         f'msg="{issue.message}" id="{issue.rule_id}"/>')
        
        output.append('</results>')
        return '\n'.join(output) + '\n'

    def _format_json(self) -> str:
        """JSON格式输出"""
        import json
        
        issues_data = []
        for issue in self.issues:
            issues_data.append({
                'file': issue.file_path,
                'line': issue.line_number,
                'column': issue.column,
                'severity': issue.severity.value,
                'message': issue.message,
                'rule_id': issue.rule_id
            })
        
        return json.dumps({'issues': issues_data}, indent=2) + '\n'


def main():
    parser = argparse.ArgumentParser(description='CAPL Static Syntax Checker')
    parser.add_argument('files', nargs='+', help='CAPL files to check')
    parser.add_argument('--format', choices=['text', 'xml', 'json'], default='text',
                       help='Output format')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress progress messages')
    
    args = parser.parse_args()
    
    checker = CAPLChecker()
    all_issues = []
    
    for file_path in args.files:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found", file=sys.stderr)
            continue
        
        if not args.quiet:
            print(f"Checking {file_path}...", file=sys.stderr)
        
        issues = checker.check_file(file_path)
        all_issues.extend(issues)
    
    # 更新checker的issues列表以包含所有文件的问题
    checker.issues = all_issues
    
    # 输出结果
    output = checker.format_issues(args.format)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
    else:
        print(output, end='')
    
    # 返回适当的退出码
    error_count = sum(1 for issue in all_issues if issue.severity == Severity.ERROR)
    return 1 if error_count > 0 else 0


if __name__ == '__main__':
    sys.exit(main())