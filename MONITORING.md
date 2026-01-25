# Process Monitoring Guide

## Overview
Process monitoring and suspicious activity detection techniques.

## Process Analysis

### Key Indicators
- Unusual parent-child relationships
- Processes with no window
- Hidden processes
- Injected threads

### Critical Processes
- lsass.exe monitoring
- csrss.exe protection
- services.exe tracking
- svchost.exe validation

## Detection Techniques

### Behavioral Analysis
- API call patterns
- File system access
- Network connections
- Registry modifications

### Memory Analysis
- Hollowed processes
- Injected DLLs
- Shellcode patterns
- RWX memory regions

## Implementation

### System Calls
- NtQuerySystemInformation
- NtQueryInformationProcess
- Process enumeration
- Thread listing

### Event Sources
- ETW providers
- Sysmon integration
- Process creation events
- Image load tracking

## Evasion Awareness
- Direct syscalls
- Process doppelganging
- Process ghosting
- Transacted hollowing

## Legal Notice
For authorized security monitoring only.
