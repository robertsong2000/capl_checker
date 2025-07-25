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
import configparser
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
    def __init__(self, config_file: str = "capl_checker.conf"):
        self.issues: List[Issue] = []
        self.variables: Dict[str, str] = {}  # variable_name -> type
        self.functions: Dict[str, Dict] = {}  # function_name -> {return_type, params}
        self.current_file = ""
        self.current_line = 0
        
        # 加载配置
        self.config = self._load_config(config_file)
        
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

    def _load_config(self, config_file: str) -> configparser.ConfigParser:
        """加载配置文件"""
        config = configparser.ConfigParser()
        
        # 设置默认值
        config.read_dict({
            'rules': {
                'enable_syntax_checks': 'true',
                'enable_style_checks': 'true',
                'enable_naming_checks': 'true',
                'enable_capl_specific_checks': 'true',
                'enable_magic_number_checks': 'true',
                'syntax_severity': 'error',
                'style_severity': 'style',
                'naming_severity': 'style',
                'capl_specific_severity': 'warning',
                'magic_number_severity': 'info'
            },
            'style': {
                'max_line_length': '120',
                'indent_size': '4',
                'use_tabs': 'false',
                'variable_naming': 'camelCase',
                'function_naming': 'camelCase',
                'constant_naming': 'UPPER_CASE',
                'signal_naming': 'PascalCase'
            },
            'capl_specific': {
                'require_variables_block': 'true',
                'require_startup_handler': 'false',
                'check_signal_names': 'true',
                'check_message_handlers': 'true',
                'check_timer_usage': 'true'
            },
            'magic_numbers': {
                'allowed_numbers': '0, 1, -1, 2, 10, 100, 1000'
            },
            'output': {
                'default_format': 'text',
                'show_rule_ids': 'true',
                'show_columns': 'true',
                'use_colors': 'true'
            }
        })
        
        # 尝试读取配置文件
        if os.path.exists(config_file):
            try:
                config.read(config_file)
            except Exception as e:
                print(f"Warning: Could not read config file {config_file}: {e}", file=sys.stderr)
        
        return config

    def _is_rule_enabled(self, rule_category: str) -> bool:
        """检查规则类别是否启用"""
        return self.config.getboolean('rules', f'enable_{rule_category}_checks', fallback=True)

    def _get_severity(self, rule_category: str) -> Severity:
        """获取规则类别的严重程度"""
        severity_str = self.config.get('rules', f'{rule_category}_severity', fallback='warning')
        try:
            return Severity(severity_str)
        except ValueError:
            return Severity.WARNING

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
        if not self._is_rule_enabled('style'):
            return
            
        max_length = self.config.getint('style', 'max_line_length', fallback=120)
        if len(line.rstrip()) > max_length:
            self.add_issue(line_num, len(line.rstrip()), self._get_severity('style'),
                          f"Line too long ({len(line.rstrip())} > {max_length} characters)", "line-too-long")

    def _check_trailing_whitespace(self, line: str, line_num: int):
        """检查行尾空白"""
        if not self._is_rule_enabled('style'):
            return
            
        if line.rstrip() != line:
            self.add_issue(line_num, len(line.rstrip()) + 1, self._get_severity('style'),
                          "Trailing whitespace", "trailing-whitespace")

    def _check_syntax_errors(self, line: str, line_num: int):
        """检查基本语法错误"""
        if not self._is_rule_enabled('syntax'):
            return
            
        stripped = line.strip()
        
        # 检查括号匹配
        open_parens = stripped.count('(')
        close_parens = stripped.count(')')
        if open_parens != close_parens:
            self.add_issue(line_num, 0, self._get_severity('syntax'),
                          "Mismatched parentheses", "mismatched-parentheses")
        
        # 检查大括号匹配
        open_braces = stripped.count('{')
        close_braces = stripped.count('}')
        if open_braces != close_braces:
            self.add_issue(line_num, 0, self._get_severity('syntax'),
                          "Mismatched braces", "mismatched-braces")
        
        # 检查分号
        if (stripped and not stripped.endswith((';', '{', '}', ':', '\\')) 
            and not stripped.startswith(('#', 'on ', 'variables', 'includes'))
            and not any(keyword in stripped for keyword in ['if', 'else', 'while', 'for', 'do', 'switch', 'case'])):
            if not re.match(r'^\s*(//|/\*|\*)', stripped):
                self.add_issue(line_num, len(stripped), self._get_severity('syntax'),
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
        if not self._is_rule_enabled('magic_number'):
            return
            
        # 获取允许的数字
        allowed_str = self.config.get('magic_numbers', 'allowed_numbers', fallback='0, 1, -1, 2, 10, 100, 1000')
        allowed_numbers = {num.strip() for num in allowed_str.split(',')}
        
        # 查找数字
        number_pattern = r'\b(-?\d+(?:\.\d+)?)\b'
        for match in re.finditer(number_pattern, line):
            number = match.group(1)
            if number not in allowed_numbers:
                # 检查是否在注释中
                comment_pos = line.find('//')
                if comment_pos == -1 or match.start() < comment_pos:
                    self.add_issue(line_num, match.start(), self._get_severity('magic_number'),
                                  f"Magic number '{number}' should be replaced with a named constant", "magic-number")

    def _check_naming_conventions(self, line: str, line_num: int):
        """检查命名规范"""
        if not self._is_rule_enabled('naming'):
            return
            
        # 检查变量命名
        var_pattern = r'\b(int|long|float|double|char|byte|word|dword|qword)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        for match in re.finditer(var_pattern, line):
            var_name = match.group(2)
            naming_style = self.config.get('style', 'variable_naming', fallback='camelCase')
            
            if naming_style == 'camelCase' and not self._is_camel_case(var_name):
                self.add_issue(line_num, match.start(2), self._get_severity('naming'),
                              f"Variable '{var_name}' should use camelCase", "naming-convention")
            elif naming_style == 'snake_case' and not self._is_snake_case(var_name):
                self.add_issue(line_num, match.start(2), self._get_severity('naming'),
                              f"Variable '{var_name}' should use snake_case", "naming-convention")
        
        # 检查函数命名
        func_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        for match in re.finditer(func_pattern, line):
            func_name = match.group(1)
            if func_name not in self.keywords and func_name not in self.builtin_functions:
                naming_style = self.config.get('style', 'function_naming', fallback='camelCase')
                
                if naming_style == 'camelCase' and not self._is_camel_case(func_name):
                    self.add_issue(line_num, match.start(1), self._get_severity('naming'),
                                  f"Function '{func_name}' should use camelCase", "naming-convention")
                elif naming_style == 'snake_case' and not self._is_snake_case(func_name):
                    self.add_issue(line_num, match.start(1), self._get_severity('naming'),
                                  f"Function '{func_name}' should use snake_case", "naming-convention")
        
        # 检查常量命名（应该全大写）
        const_pattern = r'\b(const\s+\w+\s+)([a-zA-Z_][a-zA-Z0-9_]*)'
        match = re.search(const_pattern, line)
        if match:
            const_name = match.group(2)
            if not const_name.isupper():
                self.add_issue(line_num, match.start(2), Severity.STYLE,
                              f"Constant '{const_name}' should be UPPER_CASE", "naming-convention")

    def _is_camel_case(self, name: str) -> bool:
        """检查是否为驼峰命名"""
        return re.match(r'^[a-z][a-zA-Z0-9]*$', name) is not None

    def _is_snake_case(self, name: str) -> bool:
        """检查是否为下划线命名"""
        return re.match(r'^[a-z][a-z0-9_]*$', name) is not None

    def _check_capl_specific_issues(self, line: str, line_num: int):
        """检查CAPL特定的问题"""
        if not self._is_rule_enabled('capl_specific'):
            return
            
        # 检查setTimer使用
        if self.config.getboolean('capl_specific', 'check_timer_usage', fallback=True):
            if 'setTimer' in line:
                # 检查setTimer的参数
                timer_pattern = r'setTimer\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)'
                match = re.search(timer_pattern, line)
                if match:
                    timer_name = match.group(1).strip()
                    timer_value = match.group(2).strip()
                    
                    # 检查定时器名称是否有效
                    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', timer_name):
                        self.add_issue(line_num, match.start(1), self._get_severity('capl_specific'),
                                      f"Invalid timer name '{timer_name}'", "invalid-timer-name")
                    
                    # 检查定时器值是否为数字
                    if not re.match(r'^\d+(\.\d+)?$', timer_value):
                        self.add_issue(line_num, match.start(2), self._get_severity('capl_specific'),
                                      f"Timer value should be numeric, got '{timer_value}'", "invalid-timer-value")
        
        # 检查on message处理器
        if self.config.getboolean('capl_specific', 'check_message_handlers', fallback=True):
            if line.strip().startswith('on message'):
                # 检查消息处理器格式
                if not re.match(r'on\s+message\s+[a-zA-Z_][a-zA-Z0-9_]*\s*{?', line.strip()):
                    self.add_issue(line_num, 0, self._get_severity('capl_specific'),
                                  "Invalid message handler format", "invalid-message-handler")
        
        # 检查信号名称
        if self.config.getboolean('capl_specific', 'check_signal_names', fallback=True):
            signal_pattern = r'\$([a-zA-Z_][a-zA-Z0-9_]*)'
            for match in re.finditer(signal_pattern, line):
                signal_name = match.group(1)
                naming_style = self.config.get('style', 'signal_naming', fallback='PascalCase')
                
                if naming_style == 'PascalCase' and not self._is_pascal_case(signal_name):
                    self.add_issue(line_num, match.start(), self._get_severity('capl_specific'),
                                  f"Signal '{signal_name}' should use PascalCase", "signal-naming")

    def _is_pascal_case(self, name: str) -> bool:
        """检查是否为帕斯卡命名"""
        return re.match(r'^[A-Z][a-zA-Z0-9]*$', name) is not None

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
    parser.add_argument('--config', '-c', default='capl_checker.conf',
                       help='Configuration file (default: capl_checker.conf)')
    
    args = parser.parse_args()
    
    checker = CAPLChecker(config_file=args.config)
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