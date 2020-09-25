---
title: "FinSpy spyware analysis"
date: 2020-09-25
tags: [Mobile, Applications, FinSpy, Malware analysis]
draft: false
slug: "finspy-android"
---


We have collaborated with [Amnesty International](https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/) for whom we have analyzed a new variant of the FinSpy spyware.

{{< summary >}}


<p>By analyzing the sample we found what we suspect to be a new version of the FinFisher’s malware FinSpy for Android.</p>

<p>Even though the malware behavior and capabilities seem to be the same as what it has already been described in the past, this version goes a step further to hide the malware configuration and its capabilities.</p>

<p>This new version we named DexDen has very likely been released between May 2017 and October 2019.</p>

<p>Command and control server associated to the malware configuration is still alive by the time we wrote this report.</p>

<p>In terms of capabilities, the sample we have analyzed is meant to exfiltrate SIM card information, SMS log, call log, calendar events, address book, messages and files from 12 popular messenger applications and to track victim’s location.</p>

<p>This report provides details on how strings are obfuscated, how the communication protocol has evolved and how the extraction of three technical aspects of the malware can give insights on the malware code-base evolution.</p>

{{< /summary >}}


{{< buttonlink href="https://github.com/DefensiveLabAgency/FinSpy-for-Android/raw/master/20200806_finspy_android_analysis_public_release.pdf" text="Download the report">}}
{{< buttonlink href="https://github.com/DefensiveLabAgency/FinSpy-for-Android/" text="Analysis assets & tools" >}}