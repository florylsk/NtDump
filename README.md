# NtDump

## Description

LSASS process dumper with (mostly) NT API indirect syscalls. Currently undetected under many AV/EDR solutions.

## Usage

```powershell
.\NtDump.exe (Get-Process lsass).Id path_to_dump
```

## Credits

https://github.com/Dec0ne/HWSyscalls/
