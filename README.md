# CAPL Static Syntax Checker

一个类似于cppcheck的CAN CAPL语言静态语法检测器。

## 功能特性

- **语法检查**: 检测基本的语法错误，如括号不匹配、缺少分号等
- **变量分析**: 检测未定义变量、变量重复声明等问题
- **函数分析**: 检测函数重复声明、参数问题等
- **代码风格**: 检查命名规范、行长度、尾随空白等
- **CAPL特定检查**: 针对CAPL语言特性的专门检查
- **魔法数字检测**: 识别硬编码的数字常量
- **多种输出格式**: 支持文本、XML、JSON格式输出

## 安装和使用

### 前提条件

- Python 3.6 或更高版本

### 基本使用

```bash
# 检查单个文件
python capl_checker.py sample.can

# 检查多个文件
python capl_checker.py file1.can file2.can file3.can

# 使用自定义配置文件
python capl_checker.py --config my_config.conf sample.can

# 指定输出格式
python capl_checker.py --format xml sample.can
python capl_checker.py --format json sample.can

# 输出到文件
python capl_checker.py --output report.txt sample.can

# 静默模式（不显示进度信息）
python capl_checker.py --quiet sample.can
```

### 命令行选项

- `files`: 要检查的CAPL文件路径（必需）
- `--format`: 输出格式，可选 text、xml、json（默认：text）
- `--output`, `-o`: 输出文件路径（默认：标准输出）
- `--quiet`, `-q`: 静默模式，不显示进度信息
- `--config`: 配置文件路径（默认：capl_checker.conf）

## 检查规则

### 语法检查 (Syntax)
- `mismatched-parentheses`: 括号不匹配
- `mismatched-braces`: 大括号不匹配
- `missing-semicolon`: 缺少分号

### 变量检查 (Variables)
- `variable-redeclared`: 变量重复声明
- `undefined-variable`: 使用未定义的变量
- `unused-variable`: 未使用的变量

### 函数检查 (Functions)
- `function-redeclared`: 函数重复声明

### 代码风格 (Style)
- `line-too-long`: 行长度超过限制（默认120字符）
- `trailing-whitespace`: 行尾空白字符
- `naming-convention`: 命名规范违反

### CAPL特定检查
- `empty-message-handler`: 空的消息处理器
- `invalid-timer-usage`: 不正确的定时器使用
- `no-variables-block`: 缺少variables块
- `no-startup-handler`: 缺少启动事件处理器

### 其他检查
- `magic-number`: 魔法数字（硬编码常量）
- `file-read-error`: 文件读取错误

## 输出格式

### 文本格式（默认）
```
sample.can:15:2: style: Variable 'BadVariableName' should use camelCase [naming-convention]
sample.can:45:5: warning: Missing semicolon [missing-semicolon]
sample.can:50:15: error: Mismatched braces [mismatched-braces]

Summary: 1 errors, 2 warnings, 3 info, 5 style issues
```

### XML格式
```xml
<?xml version="1.0" encoding="UTF-8"?>
<results>
  <error file="sample.can" line="15" column="2" severity="style" 
         msg="Variable 'BadVariableName' should use camelCase" id="naming-convention"/>
  <error file="sample.can" line="45" column="5" severity="warning" 
         msg="Missing semicolon" id="missing-semicolon"/>
</results>
```

### JSON格式
```json
{
  "issues": [
    {
      "file": "sample.can",
      "line": 15,
      "column": 2,
      "severity": "style",
      "message": "Variable 'BadVariableName' should use camelCase",
      "rule_id": "naming-convention"
    }
  ]
}
```

## 配置

可以通过配置文件（默认：`capl_checker.conf`）配置检查规则和设置。配置文件使用INI格式，支持以下部分：

### [rules] 部分
控制启用的规则类别及其严重性级别：
```ini
[rules]
enable_syntax_checks = true
enable_style_checks = true
enable_naming_checks = true
enable_capl_specific_checks = true
enable_magic_number_checks = true

syntax_severity = error
style_severity = style
naming_severity = style
capl_specific_severity = warning
magic_number_severity = info
```

### [style] 部分
配置代码风格偏好：
```ini
[style]
max_line_length = 120
indent_size = 4
use_tabs = false
variable_naming = camelCase    # camelCase 或 snake_case
function_naming = camelCase    # camelCase 或 snake_case
constant_naming = UPPER_CASE
signal_naming = PascalCase
```

### [capl_specific] 部分
CAPL特定检查设置：
```ini
[capl_specific]
require_variables_block = true
require_startup_handler = false
check_signal_names = true
check_message_handlers = true
check_timer_usage = true
```

### [magic_numbers] 部分
配置允许的魔法数字：
```ini
[magic_numbers]
allowed_numbers = 0, 1, -1, 2, 10, 100, 1000
```

### [output] 部分
输出格式选项：
```ini
[output]
default_format = text
show_rule_ids = true
show_columns = true
use_colors = true
```

### 自定义配置示例
创建自定义配置文件以禁用风格检查：
```ini
[rules]
enable_style_checks = false
enable_magic_number_checks = false

[style]
variable_naming = snake_case
function_naming = snake_case
```

然后使用：
```bash
python capl_checker.py --config custom.conf sample.can
```

## 示例

项目包含一个示例CAPL文件 `sample.can`，其中包含各种CAPL构造和一些故意的问题，用于测试检测器的功能。

运行示例：
```bash
python capl_checker.py sample.can
```

## 扩展

这个工具可以通过以下方式扩展：

1. **添加新的检查规则**: 在 `CAPLChecker` 类中添加新的检查方法
2. **改进解析**: 实现更复杂的AST解析以进行深度分析
3. **配置文件支持**: 实现配置文件解析以自定义规则
4. **IDE集成**: 创建插件以集成到常用的IDE中
5. **数据库支持**: 添加对CAN数据库文件的支持以验证信号和消息

## 限制

当前版本的限制：

- 简化的语法解析，可能无法处理所有复杂的CAPL构造
- 有限的数据流分析
- 不支持预处理器指令
- 不支持CAN数据库文件验证

## 贡献

欢迎提交问题报告和功能请求。如果您想贡献代码，请：

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 创建 Pull Request

## 许可证

MIT License