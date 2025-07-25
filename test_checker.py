#!/usr/bin/env python3
"""
Test script for CAPL Static Syntax Checker
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path

def create_test_file(content: str) -> str:
    """创建临时测试文件"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.can', delete=False) as f:
        f.write(content)
        return f.name

def run_checker(file_path: str, format_type: str = 'text') -> str:
    """运行检测器并返回输出"""
    cmd = [sys.executable, 'capl_checker.py', '--format', format_type, file_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def test_basic_syntax():
    """测试基本语法检查"""
    print("Testing basic syntax checks...")
    
    # 测试括号不匹配
    test_content = """
variables {
    int test;
}

void testFunc() {
    if (test > 0 {  // 缺少右括号
        test = 1;
    }
}
"""
    
    test_file = create_test_file(test_content)
    output = run_checker(test_file)
    
    if "mismatched-parentheses" in output:
        print("✓ Parentheses mismatch detection works")
    else:
        print("✗ Parentheses mismatch detection failed")
    
    os.unlink(test_file)

def test_variable_checks():
    """测试变量检查"""
    print("Testing variable checks...")
    
    # 测试未定义变量
    test_content = """
variables {
    int definedVar;
}

void testFunc() {
    definedVar = 1;
    undefinedVar = 2;  // 未定义变量
}
"""
    
    test_file = create_test_file(test_content)
    output = run_checker(test_file)
    
    if "undefined-variable" in output:
        print("✓ Undefined variable detection works")
    else:
        print("✗ Undefined variable detection failed")
    
    os.unlink(test_file)

def test_naming_conventions():
    """测试命名规范"""
    print("Testing naming conventions...")
    
    test_content = """
variables {
    int BadVariableName;  // 应该是camelCase
    int goodVariableName;
}
"""
    
    test_file = create_test_file(test_content)
    output = run_checker(test_file)
    
    if "naming-convention" in output:
        print("✓ Naming convention check works")
    else:
        print("✗ Naming convention check failed")
    
    os.unlink(test_file)

def test_magic_numbers():
    """测试魔法数字检查"""
    print("Testing magic number detection...")
    
    test_content = """
variables {
    int test;
}

void testFunc() {
    test = 42;  // 魔法数字
    test = 1;   // 不是魔法数字
}
"""
    
    test_file = create_test_file(test_content)
    output = run_checker(test_file)
    
    if "magic-number" in output:
        print("✓ Magic number detection works")
    else:
        print("✗ Magic number detection failed")
    
    os.unlink(test_file)

def test_capl_specific():
    """测试CAPL特定检查"""
    print("Testing CAPL-specific checks...")
    
    # 测试缺少variables块
    test_content = """
void testFunc() {
    int test = 1;
}
"""
    
    test_file = create_test_file(test_content)
    output = run_checker(test_file)
    
    if "no-variables-block" in output:
        print("✓ Missing variables block detection works")
    else:
        print("✗ Missing variables block detection failed")
    
    os.unlink(test_file)

def test_output_formats():
    """测试输出格式"""
    print("Testing output formats...")
    
    test_content = """
variables {
    int BadVariableName;
}
"""
    
    test_file = create_test_file(test_content)
    
    # 测试XML格式
    xml_output = run_checker(test_file, 'xml')
    if '<?xml version="1.0"' in xml_output and '<results>' in xml_output:
        print("✓ XML format works")
    else:
        print("✗ XML format failed")
    
    # 测试JSON格式
    json_output = run_checker(test_file, 'json')
    if '"issues":' in json_output:
        print("✓ JSON format works")
    else:
        print("✗ JSON format failed")
    
    os.unlink(test_file)

def test_sample_file():
    """测试示例文件"""
    print("Testing sample.can file...")
    
    if os.path.exists('sample.can'):
        output = run_checker('sample.can')
        
        # 检查是否检测到预期的问题
        expected_issues = [
            'naming-convention',
            'magic-number',
            'missing-semicolon',
            'mismatched-parentheses'
        ]
        
        detected_issues = []
        for issue in expected_issues:
            if issue in output:
                detected_issues.append(issue)
        
        print(f"✓ Detected {len(detected_issues)}/{len(expected_issues)} expected issues in sample.can")
        
        if len(detected_issues) < len(expected_issues):
            missing = set(expected_issues) - set(detected_issues)
            print(f"  Missing: {', '.join(missing)}")
    else:
        print("✗ sample.can file not found")

def main():
    """运行所有测试"""
    print("CAPL Checker Test Suite")
    print("=" * 40)
    
    # 确保在正确的目录中
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    if not os.path.exists('capl_checker.py'):
        print("Error: capl_checker.py not found in current directory")
        sys.exit(1)
    
    # 运行测试
    test_basic_syntax()
    test_variable_checks()
    test_naming_conventions()
    test_magic_numbers()
    test_capl_specific()
    test_output_formats()
    test_sample_file()
    
    print("\nTest suite completed!")

if __name__ == '__main__':
    main()