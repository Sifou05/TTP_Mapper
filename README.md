# TTP Mapper

A command-line tool for mapping threat actors to MITRE ATT&CK techniques.

## Features
- Search for threat actors/groups and view their techniques
- Search for techniques and see which groups use them
- Uses official MITRE ATT&CK Enterprise dataset

## Installation

1. Clone this repository
2. Download the MITRE ATT&CK dataset from [MITRE's GitHub](https://github.com/mitre/cti)
3. Place `enterprise-attack.json` in the project directory

## Usage

Run the tool:
```
python ttp_mapper.py
```

Commands:
- `group <name>` - Search for a threat actor
- `technique <name>` - Search for a technique
- `quit` - Exit

## Examples
```
> group lazarus
> technique powershell
```

## Technologies
- Python 3
- MITRE ATT&CK Framework
```

**2. Create a .gitignore file** (don't upload the large JSON file):
```
enterprise-attack.json
*.pyc
__pycache__/
