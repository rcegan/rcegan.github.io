---
title: "'Attempted UAC Bypass via iscsicpl.exe' Sentinel detection"
date: 2022-07-20T00:00:00Z
draft: false
---
# The UAC Bypass
I was tipped off to the UAC bypass by [this](https://twitter.com/wdormann/status/1547583317410607110) post from Will Dormann. I quickly found [another tweet](https://twitter.com/nas_bench/status/1549417732910768132) by @nas_bench with a Sigma rule to detect it. I jumped on Uncoder and generated the below query:

```
DeviceImageLoadEvents 
| where (InitiatingProcessFolderPath =~ @"C:\Windows\SysWOW64\iscsicpl.exe" and not (FolderPath contains @"C:\Windows\" and FolderPath contains "iscsiexe.dll"))
```

I've created a KQL file with entity mappings on my [github](https://github.com/rcegan/KQL-Tomfoolery/blob/main/Image%20Load/Attempt%20to%20bypass%20UAC%20via%20iscsicpl.exe.kql).