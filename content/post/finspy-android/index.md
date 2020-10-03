---
title: "FinSpy spyware analysis"
date: 2020-09-25
tags: [Mobile, Applications, FinSpy, Malware analysis]
draft: false
slug: "finspy-android"
---


We have collaborated with [Amnesty International](https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/) for whom we have analyzed a new variant of the FinSpy spyware.


# Executive summary
{{< summary >}}


<p>By analyzing the sample we found what we suspect to be a new version of the FinFisher’s malware FinSpy for Android.</p>

<p>Even though the malware behavior and capabilities seem to be the same as what it has already been described in the past, this version goes a step further to hide the malware configuration and its capabilities.</p>

<p>This new version we named DexDen has very likely been released between May 2017 and October 2019.</p>

<p>Command and control server associated to the malware configuration is still alive by the time we wrote this report.</p>

<p>In terms of capabilities, the sample we have analyzed is meant to exfiltrate SIM card information, SMS log, call log, calendar events, address book, messages and files from 12 popular messenger applications and to track victim’s location.</p>

<p>This report provides details on how strings are obfuscated, how the communication protocol has evolved and how the extraction of three technical aspects of the malware can give insights on the malware code-base evolution.</p>

{{< /summary >}}


{{< buttonlink href="https://github.com/DefensiveLabAgency/FinSpy-for-Android/" text="Analysis assets & tools on GitHub" >}}

{{< buttonlink href="https://www.amnesty.org/en/latest/research/2020/09/german-made-finspy-spyware-found-in-egypt-and-mac-and-linux-versions-revealed/" text="Report by Amnesty International" >}}

{{< toc >}}

# Overview
This report focuses on the analysis of the sample described below.

<div class="panel">
    <p class="panel-heading mb-0">Sample file</p>
    <div class="panel-block">
        <table class="table is-narrow is-size-7 is-borderless">
            <tbody>
            <tr>
                <td>Filename</td>
                <td><code>WIFI.apk</code></td>
            </tr>
            <tr>
                <td>Size</td>
                <td><code>2.87MB</code></td>
            </tr>
            <tr>
                <td>MD5</td>
                <td><code>79ba96848428337e685e10b06ccc1c89</code></td>
            </tr>
            <tr>
                <td>SHA-1</td>
                <td><code>51b31827c1d961ced142a3c5f3efa2b389f9c5ad</code></td>
            </tr>
            <tr>
                <td>SHA-256</td>
                <td><code>854774a198db490a1ae9f06d5da5fe6a1f683bf3d7186e56776516f982d41ad3</code></td>
            </tr>
            <tr>
                <td>Application name</td>
                <td><code>wifi</code></td>
            </tr>
            <tr>
                <td>Package</td>
                <td><code>org.xmlpush.v3</code></td>
            </tr>
            <tr>
                <td>Main activity</td>
                <td><code>org.xmlpush.v3.StartVersion</code></td>
            </tr>
            </tbody>
        </table>
    </div>
</div>

<div class="panel">
    <p class="panel-heading mb-0">Sample certificate</p>
    <div class="panel-block">
        <table class="table is-narrow is-size-7 is-borderless">
            <tbody>
                <tr>
                    <td>Subject</td>
                    <td><code>CN='MITAS Ltd.'</code></td>
                </tr>
                <tr>
                    <td>Signature Alg.</td>
                    <td><code>rsassa_pkcs1v15</code></td>
                </tr>
                <tr>
                    <td>Validity</td>
                    <td><code>2017-05-27</code> - <code>2023-05-26</code></td>
                </tr>
                <tr>
                    <td>Issuer</td>
                    <td><code>CN='MITAS Ltd.'</code></td>
                </tr>
                <tr>
                    <td>Hash Alg.</td>
                    <td><code>sha256</code></td>
                </tr>
                <tr>
                    <td>MD5</td>
                    <td><code>b99ac605872a55e609854176413e603c</code></td>
                </tr>
                <tr>
                    <td>SHA-1</td>
                    <td><code>7c6e4f2e84ebaa8d25040f63d840e14f6f822125</code></td>
                </tr>
                <tr>
                    <td>SHA-256</td>
                    <td><code>8052584eacfd199602b348ef60e20c246ec929d62bc5b85fd0e60ba3205b05a2</code></td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

For this analysis we use the following tools:

* [Aether](https://defensive-lab.agency/en/products/aether/) to analyze CFG
* [Javalang](https://github.com/c2nes/javalang) to parse the Java code
* [Smalisca](https://github.com/U039b/smalisca) to analyze the Smali code
* [Yara](https://virustotal.github.io/yara/) to detect FinSpy variants
* [FinSpy tools](https://github.com/devio/FinSpy-Tools/) to parse the FinSpy configuration

We share the following assets on [our GitHub repository](https://github.com/DefensiveLabAgency/FinSpy-for-Android/):

* `java_parser.py` to extract obfuscated from Java code
* `string_decoder.py` to decode obfuscated strings
* `table.ods` containing TLV types and decoded strings
* `FinSpy.yar` Yara rules detecting FinSpy variants

## Tiny tools
### Yara rules

```bash
rule FinSpy_ConfigInAPK : android apkhideconfig finspy
{
	meta:
		description = "Detect FinFisher FinSpy configuration in APK file. Probably the original FinSpy version."
		date = "2020/08/05"
		reference = "https://github.com/devio/FinSpy-Tools"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"

	strings:
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/

	condition:
		uint32(0) == 0x04034b50 and $re and (#re > 50)
}

rule FinSpy_DexDen : android dexhideconfig finspy
{
	meta:
		description = "Detect FinFisher FinSpy configuration in DEX file. Probably a newer FinSpy variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"

	strings:
		$config_1 = { 90 5b fe 00 }
		$config_2 = { 70 37 80 00 }
		$config_3 = { 40 38 80 00 }
		$config_4 = { a0 33 84 }
		$config_5 = { 90 79 84 00 }

	condition:
		uint16(0) == 0x6564 and
		#config_1 >= 2 and 
		#config_2 >= 2 and 
		#config_3 >= 2 and 
		#config_4 >= 2 and 
		#config_5 >= 2
}

rule FinSpy_TippyTime: finspyTT
{
	meta:
		description = "Detect FinFisher FinSpy 'TippyTime' variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"
	strings:
		$config_1 = { 90 5b fe 00 }
		$config_2 = { 70 37 80 00 }
		$config_3 = { 40 38 80 00 }
		$config_4 = { a0 33 84 }
		$config_5 = { 90 79 84 00 }
		$timestamp = { 95 E9 D1 5B }

	condition:
		uint16(0) == 0x6564 and
		$timestamp and
		$config_1 and 
		$config_2 and 
		$config_3 and 
		$config_4 and 
		$config_5
}

rule FinSpy_TippyPad: finspyTP
{
	meta:
		description = "Detect FinFisher FinSpy 'TippyPad' variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"
	strings:
		$pad_1 = "0123456789abcdef"
		$pad_2 = "fedcba9876543210"

	condition:
		uint16(0) == 0x6564 and
		#pad_1 > 50 and
		#pad_2 > 50
}
```


### Script to plot CFG
```python
import networkx as nx
from androguard.misc import AnalyzeAPK
from graphviz import Digraph as dg

apk = '<path to you APK>'
a, d, dx = AnalyzeAPK(apk)
call_graph = dx.get_call_graph()
graph = nx.empty_graph()


def clean_name(name):
    return name[0:name.rfind(')')+1]


graphs = {
    'audio': [
        {
            'class': 'Landroid/media/AudioRecord',
            'method': 'startRecording'
        },
        {
            'class': 'Landroid/media/AudioManager',
            'method': 'setMicrophoneMute'
        },
    ],
    'read_sms_configuration': [
        {
            'class': 'Landroid/telephony/SmsMessage',
            'method': 'getPdu'
        },
        {
            'class': 'Landroid/telephony/SmsMessage',
            'method': 'getMessageBody'
        },
        {
            'class': 'Landroid/telephony/SmsMessage',
            'method': 'getUserData'
        },
        {
            'class': 'Lorg/xmlpush/v3/q/c',
            'method': '<init>'
        },
        {
            'class': 'Lorg/xmlpush/v3/q/c',
            'method': 'a',
            'starts_with': 'Lorg/xmlpush/v3/q/c;->a([Ljava'
        },
    ],
}

for g in graphs:
    fg = dg(engine='dot',
            format='png',
            graph_attr={'overlap': 'orthoxy',
                        'diredgeconstraints': 'true',
                        'splines': 'ortho'},
            node_attr={'shape': 'box',
                       'style': 'filled',
                       'fontcolor': '#212529',
                       'fontsize': '10',
                       'fontname': 'sans-serif'})

    methods = []
    for search in graphs[g]:
        for m in dx.find_methods(methodname=search['method'], classname=search['class']):
            if 'starts_with' in search:
                cm = clean_name(str(m.get_method()))
                if cm.startswith(search['starts_with']):
                    methods.append(m)
            else:
                methods.append(m)

    for m in methods:
        fg.node(clean_name(str(m.get_method())), color='#985e6d', fontcolor='white')
        ancestors = nx.ancestors(call_graph, m.get_method())
        ancestors.add(m.get_method())
        graph = call_graph.subgraph(ancestors)
        for n, d in graph.in_degree():
            if d == 0:
                fg.node(clean_name(str(n)), color='#494e6b', fontcolor='white')
        for u, v in graph.edges:
            fg.edge(clean_name(str(u)), clean_name(str(v)))

    fg.render(g)
```

# A suspected new FinSpy version
FinSpy capabilities and technical aspects are widely documented online. In this section we focus on what we suspect to be clues of a new version of FinSpy for Android.

To do so, we investigate on the following parameters:

* location of the FinSpy configuration
* string obfuscation
* local socket address generation
* unknown TLV types

## Configuration storage
As far as we know, FinSpy stores its configuration into APK metadata. It was well documented and extraction tools are available online:

* https://github.com/devio/FinSpy-Tools
* https://github.com/SpiderLabs/malware-analysis/blob/master/Ruby/FinSpy/

The sample we investigate on shows that the FinSpy configuration is stored into the DEX file.

{{< fig src="img/configuration.png" caption="FinSpy configuration stored into the DEX" >}}

Even if existing extraction tools failed to extract the configuration from the DEX, parsing tools succeeded to parse it. The structure of the configuration remains the same, only its storage location has changed.

We name this FinSpy variant **DexDen**.

## String obfuscation
As far as we know, FinSpy strings defined in its code are not obfuscated. The sample we analyze is different, all Java strings are obfuscated. Each Java class using strings implements the following 2 Java methods:

* `String OOOoOoiIoIIiO0o01I1I00(final int index)` returning the obfuscated string as bytes at the given index.
* `byte[] i1IlIil011Iiil(final byte[] array, final byte[] array2)` decoding an obfuscated string.

{{< fig src="img/string-obfuscation.png" caption="Example of obfuscated strings and the two decoding TippyPads" >}}

{{< fig src="img/string-decoding.png" caption="Example of the Java method decoding obfuscated strings" >}}

Strings are decoded by XORing of the obfuscated one with one of the two pads. The pad is selected according to the index mod 2. Pads are the same for all Java classes using strings:

* `0123456789abcdef`
* `fedcba9876543210`

We have developed a Python script parsing the entire Java code to retrieve obfuscated strings `java_parser.py` and one to decode them `string_decoder.py`.

We denote this kind of string obfuscation **TippyPad** for short.

## Local socket address generation
FinSpy uses Unix socket to communicate between threads. The local socket address is generated by hashing the values of the following system properties:

* `ro.product.model`
* `ro.product.brand`
* `ro.product.name`
* `ro.product.device`
* `ro.product.manufacturer`
* `ro.build.fingerprint`

An utility method meant to encode data and generate local socket address uses the timestamp `1540483477` corresponding to `Thu 25 October 2018 16:04:37 UTC`. Java method generating local socket address is listed below.

{{< fig src="img/socket-address.png" caption="Java method generating the local socket address" >}}

We denote this kind of address generation **TippyTime** for short.

## Unknown TLV types
After leaks about FinFisher and FinSpy, community has reversed the different TLV values used in data marshaling/unmarshaling to ensure a common data format between C2s and implants. These values are available online:
https://github.com/devio/FinSpy-Tools/blob/master/Android/finspyCfgParse.py

The FinSpy version we analyze seems to be using unknown TLV values. To get some meaning about the different unknown TLV values, we reversed existing values. We were able to detect semantic groups based on the binary representation of these values. 

The Python script we developed recovers groups based on existing values. Then parses the sample Smali code to extract unknown TLV values. We used a [patched version of Smalisca](https://github.com/U039b/smalisca) to do so. We have extracted the following suspected unknown TLV values. The entire list of TLV and groups is available in the GitHub repository.

To determine the group the TLV value belongs to just mask that value with `0xFFFFF800`.

<table class="table is-striped is-bordered is-size-7 is-narrow">
<tbody>
<tr class="has-text-centered has-text-primary-dark"><td>Group ID</td><td>Group name</td><td>TLV value</td><td>Known TLV</td><td>TLV name</td></tr>
<tr><td>64</td><td>drives all get</td><td>131488</td><td>✔</td><td>TlvTypeGetAllDrivesRequest</td></tr>
<tr><td>64</td><td>drives all get</td><td>131744</td><td>✔</td><td>TlvTypeGetAllDrivesReply</td></tr>
<tr><td>66</td><td>contents folder get</td><td>135328</td><td>✔</td><td>TlvTypeGetFolderContentsRequest</td></tr>
<tr><td>66</td><td>contents folder get</td><td>135584</td><td>✔</td><td>TlvTypeGetFolderContentsReply</td></tr>
<tr><td>66</td><td>contents folder get</td><td>135840</td><td>✔</td><td>TlvTypeGetFolderContentsNext</td></tr>
<tr><td>66</td><td>contents folder get</td><td>136096</td><td>✔</td><td>TlvTypeGetFolderContentsEnd</td></tr>
<tr><td>68</td><td>download file</td><td>139424</td><td>✔</td><td>TlvTypeDownloadFileRequest</td></tr>
<tr><td>68</td><td>download file</td><td>139680</td><td>✔</td><td>TlvTypeCancelDownloadFileRequest</td></tr>
<tr><td>68</td><td>download file</td><td>139936</td><td>✔</td><td>TlvTypeDownloadFileReply</td></tr>
<tr><td>68</td><td>download file</td><td>140192</td><td>✔</td><td>TlvTypeDownloadFileNext</td></tr>
<tr><td>68</td><td>download file</td><td>140448</td><td>✔</td><td>TlvTypeDownloadFileEnd</td></tr>
<tr><td>68</td><td>download file</td><td>140704</td><td>✔</td><td>TlvTypeCancelDownloadFileReply</td></tr>
<tr><td>70</td><td>upload file</td><td>143520</td><td>✔</td><td>TlvTypeUploadFileRequest</td></tr>
<tr><td>70</td><td>upload file</td><td>143776</td><td>✔</td><td>TlvTypeCancelUploadFileRequest</td></tr>
<tr><td>70</td><td>upload file</td><td>144032</td><td>✔</td><td>TlvTypeUploadFileReply</td></tr>
<tr><td>70</td><td>upload file</td><td>144288</td><td>✔</td><td>TlvTypeUploadFileNext</td></tr>
<tr><td>70</td><td>upload file</td><td>144544</td><td>✔</td><td>TlvTypeUploadFileEnd</td></tr>
<tr><td>70</td><td>upload file</td><td>144800</td><td>✔</td><td>TlvTypeUploadFileCompleted</td></tr>
<tr><td>70</td><td>upload file</td><td>145056</td><td>✔</td><td>TlvTypeCancelUploadFileReply</td></tr>
<tr><td>72</td><td>delete file</td><td>147616</td><td>✔</td><td>TlvTypeDeleteFileRequest</td></tr>
<tr><td>72</td><td>delete file</td><td>147872</td><td>✔</td><td>TlvTypeDeleteFileReply</td></tr>
<tr><td>74</td><td>search file</td><td>151968</td><td>✔</td><td>TlvTypeSearchFileRequest</td></tr>
<tr><td>74</td><td>search file</td><td>152224</td><td>✔</td><td>TlvTypeSearchFileReply</td></tr>
<tr><td>74</td><td>search file</td><td>152480</td><td>✔</td><td>TlvTypeSearchFileNext</td></tr>
<tr><td>74</td><td>search file</td><td>152736</td><td>✔</td><td>TlvTypeSearchFileEnd</td></tr>
<tr><td>74</td><td>search file</td><td>152992</td><td>✔</td><td>TlvTypeCancelSearchFileRequest</td></tr>
<tr><td>74</td><td>search file</td><td>153248</td><td>✔</td><td>TlvTypeCancelSearchFileReply</td></tr>
<tr><td>78</td><td>fs</td><td>159888</td><td>✔</td><td>TlvTypeFSFileDataChunk</td></tr>
<tr><td>78</td><td>fs</td><td>160128</td><td>✔</td><td>TlvTypeFSDiskDrive</td></tr>
<tr><td>78</td><td>fs</td><td>160384</td><td>✔</td><td>TlvTypeFSFullPath</td></tr>
<tr><td>78</td><td>fs</td><td>160640</td><td>✔</td><td>TlvTypeFSFilename</td></tr>
<tr><td>78</td><td>fs</td><td>160896</td><td>✔</td><td>TlvTypeFSFileExtension</td></tr>
<tr><td>78</td><td>fs</td><td>161088</td><td>✔</td><td>TlvTypeFSDiskDriveType</td></tr>
<tr><td>78</td><td>fs</td><td>161408</td><td>✔</td><td>TlvTypeFSFileSize</td></tr>
<tr><td>78</td><td>fs</td><td>161584</td><td>✔</td><td>TlvTypeFSIsFolder</td></tr>
<tr><td>79</td><td>fs</td><td>161840</td><td>✔</td><td>TlvTypeFSReadOnly</td></tr>
<tr><td>79</td><td>fs</td><td>162096</td><td>✔</td><td>TlvTypeFSHidden</td></tr>
<tr><td>79</td><td>fs</td><td>162352</td><td>✔</td><td>TlvTypeFSSystem</td></tr>
<tr><td>79</td><td>fs</td><td>162688</td><td>✔</td><td>TlvTypeFSFileCreationTime</td></tr>
<tr><td>79</td><td>fs</td><td>162944</td><td>✔</td><td>TlvTypeFSFileLastAccessTime</td></tr>
<tr><td>79</td><td>fs</td><td>163200</td><td>✔</td><td>TlvTypeFSFileLastWriteTime</td></tr>
<tr><td>79</td><td>fs</td><td>163472</td><td>✔</td><td>TlvTypeFSFullPathM</td></tr>
<tr><td>79</td><td>fs</td><td>163632</td><td>×</td><td>unknown</td></tr>
<tr><td>82</td><td>system config file</td><td>168096</td><td>✔</td><td>TlvTypeGetFileSystemConfigRequest</td></tr>
<tr><td>82</td><td>system config file</td><td>168352</td><td>✔</td><td>TlvTypeFileSystemConfigReply</td></tr>
<tr><td>82</td><td>system config file</td><td>168608</td><td>✔</td><td>TlvTypeSetFileSystemConfigRequest</td></tr>
<tr><td>128</td><td>line cmd</td><td>262560</td><td>✔</td><td>TlvTypeStartCmdLineSessionRequest</td></tr>
<tr><td>128</td><td>line cmd</td><td>262816</td><td>✔</td><td>TlvTypeStartCmdLineSessionReply</td></tr>
<tr><td>128</td><td>line cmd</td><td>263072</td><td>✔</td><td>TlvTypeStopCmdLineSessionRequest</td></tr>
<tr><td>128</td><td>line cmd</td><td>263328</td><td>✔</td><td>TlvTypeCmdLineSessionStoppedReply</td></tr>
<tr><td>128</td><td>line cmd</td><td>263584</td><td>✔</td><td>TlvTypeCmdLineExecute</td></tr>
<tr><td>128</td><td>line cmd</td><td>263840</td><td>✔</td><td>TlvTypeCmdLineExecutionResult</td></tr>
<tr><td>130</td><td>line cmd execute</td><td>266352</td><td>✔</td><td>TlvTypeCmdLineExecuteCommand</td></tr>
<tr><td>130</td><td>line cmd execute</td><td>266560</td><td>✔</td><td>TlvTypeCmdLineExecuteAnswerID</td></tr>
<tr><td>130</td><td>line cmd execute</td><td>266864</td><td>✔</td><td>TlvTypeCmdLineExecuteAnswerData</td></tr>
<tr><td>146</td><td>line config cmd</td><td>299168</td><td>✔</td><td>TlvTypeGetCmdLineConfigRequest</td></tr>
<tr><td>146</td><td>line config cmd</td><td>299424</td><td>✔</td><td>TlvTypeCmdLineConfigReply</td></tr>
<tr><td>146</td><td>line config cmd</td><td>299680</td><td>✔</td><td>TlvTypeSetCmdLineConfigRequest</td></tr>
<tr><td>160</td><td>config scheduler</td><td>328096</td><td>✔</td><td>TlvTypeGetSchedulerConfigRequest</td></tr>
<tr><td>160</td><td>config scheduler</td><td>328352</td><td>✔</td><td>TlvTypeSchedulerConfigReply</td></tr>
<tr><td>160</td><td>config scheduler</td><td>328608</td><td>✔</td><td>TlvTypeSetSchedulerConfigRequest</td></tr>
<tr><td>162</td><td>task scheduler</td><td>331920</td><td>✔</td><td>TlvTypeSchedulerTask</td></tr>
<tr><td>162</td><td>task scheduler</td><td>332192</td><td>✔</td><td>TlvTypeSchedulerTaskRecordByTime</td></tr>
<tr><td>162</td><td>task scheduler</td><td>332448</td><td>✔</td><td>TlvTypeSchedulerTaskRecordScreenWhenAppRuns</td></tr>
<tr><td>162</td><td>task scheduler</td><td>332704</td><td>✔</td><td>TlvTypeSchedulerTaskRecordMicWhenAppUsesIt</td></tr>
<tr><td>162</td><td>task scheduler</td><td>332960</td><td>✔</td><td>TlvTypeSchedulerTaskRecordWebCamWhenAppUsesIt</td></tr>
<tr><td>176</td><td>sch</td><td>360592</td><td>✔</td><td>TlvTypeSCHTaskConfiguration</td></tr>
<tr><td>176</td><td>sch</td><td>360752</td><td>✔</td><td>TlvTypeSCHTaskEnabled</td></tr>
<tr><td>176</td><td>sch</td><td>361344</td><td>✔</td><td>TlvTypeSCHTaskStartDateTime</td></tr>
<tr><td>176</td><td>sch</td><td>361600</td><td>✔</td><td>TlvTypeSCHTaskStopDateTime</td></tr>
<tr><td>176</td><td>sch</td><td>362112</td><td>✔</td><td>TlvTypeSCHApplicationName</td></tr>
<tr><td>176</td><td>sch</td><td>362288</td><td>✔</td><td>TlvTypeSCHApplicationWindowOnly</td></tr>
<tr><td>512</td><td>microphone</td><td>1048992</td><td>✔</td><td>TlvTypeStartMicrophoneRequest</td></tr>
<tr><td>512</td><td>microphone</td><td>1049248</td><td>✔</td><td>TlvTypeStartMicrophoneReply</td></tr>
<tr><td>512</td><td>microphone</td><td>1049504</td><td>✔</td><td>TlvTypeMicrophoneFrame</td></tr>
<tr><td>512</td><td>microphone</td><td>1049760</td><td>✔</td><td>TlvTypeStopMicrophoneRequest</td></tr>
<tr><td>512</td><td>microphone</td><td>1050016</td><td>✔</td><td>TlvTypeMicrophoneStoppedReply</td></tr>
<tr><td>512</td><td>microphone</td><td>1050272</td><td>✔</td><td>TlvTypeStartMicrophoneRecording</td></tr>
<tr><td>514</td><td></td><td>1052736</td><td>✔</td><td>TlvTypeMICFrameID</td></tr>
<tr><td>514</td><td></td><td>1053072</td><td>✔</td><td>TlvTypeMICFrameData</td></tr>
<tr><td>514</td><td></td><td>1053312</td><td>✔</td><td>TlvTypeAudioSessionType</td></tr>
<tr><td>514</td><td></td><td>1053568</td><td>✔</td><td>TlvTypeAudioEncodingType</td></tr>
<tr><td>518</td><td>audio config</td><td>1061024</td><td>✔</td><td>TlvTypeGetAudioConfigRequest</td></tr>
<tr><td>518</td><td>audio config</td><td>1061280</td><td>✔</td><td>TlvTypeAudioConfigReply</td></tr>
<tr><td>518</td><td>audio config</td><td>1061536</td><td>✔</td><td>TlvTypeSetAudioConfigRequest</td></tr>
<tr><td>520</td><td>type video</td><td>1066112</td><td>✔</td><td>TlvTypeVideoSessionType</td></tr>
<tr><td>520</td><td>type video</td><td>1066368</td><td>✔</td><td>TlvTypeVideoEncodingType</td></tr>
<tr><td>544</td><td>screen</td><td>1114528</td><td>✔</td><td>TlvTypeStartScreenRequest</td></tr>
<tr><td>544</td><td>screen</td><td>1114784</td><td>✔</td><td>TlvTypeStartScreenReply</td></tr>
<tr><td>544</td><td>screen</td><td>1115040</td><td>✔</td><td>TlvTypeScreenFrame</td></tr>
<tr><td>544</td><td>screen</td><td>1115296</td><td>✔</td><td>TlvTypeStopScreenRequest</td></tr>
<tr><td>544</td><td>screen</td><td>1115552</td><td>✔</td><td>TlvTypeScreenStoppedReply</td></tr>
<tr><td>544</td><td>screen</td><td>1115808</td><td>✔</td><td>TlvTypeStartScreenRecording</td></tr>
<tr><td>548</td><td>cam web</td><td>1122720</td><td>✔</td><td>TlvTypeStartWebCamRequest</td></tr>
<tr><td>548</td><td>cam web</td><td>1122976</td><td>✔</td><td>TlvTypeStartWebCamReply</td></tr>
<tr><td>548</td><td>cam web</td><td>1123232</td><td>✔</td><td>TlvTypeWebCamFrame</td></tr>
<tr><td>548</td><td>cam web</td><td>1123488</td><td>✔</td><td>TlvTypeStopWebCamRequest</td></tr>
<tr><td>548</td><td>cam web</td><td>1123744</td><td>✔</td><td>TlvTypeWebCamStoppedReply</td></tr>
<tr><td>548</td><td>cam web</td><td>1124000</td><td>✔</td><td>TlvTypeStartWebCamRecording</td></tr>
<tr><td>550</td><td>config video</td><td>1126560</td><td>✔</td><td>TlvTypeGetVideoConfigRequest</td></tr>
<tr><td>550</td><td>config video</td><td>1126816</td><td>✔</td><td>TlvTypeVideoConfigReply</td></tr>
<tr><td>550</td><td>config video</td><td>1127072</td><td>✔</td><td>TlvTypeSetVideoConfigRequest</td></tr>
<tr><td>552</td><td></td><td>1130560</td><td>✔</td><td>TlvTypeVDFrameID</td></tr>
<tr><td>552</td><td></td><td>1130896</td><td>✔</td><td>TlvTypeVDFrameData</td></tr>
<tr><td>552</td><td></td><td>1131136</td><td>✔</td><td>TlvTypeOriginalVideoResolution</td></tr>
<tr><td>552</td><td></td><td>1131392</td><td>✔</td><td>TlvTypeVideoResolution</td></tr>
<tr><td>552</td><td></td><td>1132160</td><td>✔</td><td>TlvTypeAutomaticRecordingUID</td></tr>
<tr><td>576</td><td>key logging</td><td>1180064</td><td>✔</td><td>TlvTypeStartKeyLoggingRequest</td></tr>
<tr><td>576</td><td>key logging</td><td>1180320</td><td>✔</td><td>TlvTypeStartKeyLoggingReply</td></tr>
<tr><td>576</td><td>key logging</td><td>1180576</td><td>✔</td><td>TlvTypeKeyLoggingFrame</td></tr>
<tr><td>576</td><td>key logging</td><td>1180832</td><td>✔</td><td>TlvTypeStopKeyLoggingRequest</td></tr>
<tr><td>576</td><td>key logging</td><td>1181088</td><td>✔</td><td>TlvTypeKeyLoggingStoppedReply</td></tr>
<tr><td>582</td><td>config keylogger</td><td>1192096</td><td>✔</td><td>TlvTypeGetKeyloggerConfigRequest</td></tr>
<tr><td>582</td><td>config keylogger</td><td>1192352</td><td>✔</td><td>TlvTypeKeyloggerConfigReply</td></tr>
<tr><td>582</td><td>config keylogger</td><td>1192608</td><td>✔</td><td>TlvTypeSetKeyloggerConfigRequest</td></tr>
<tr><td>584</td><td>kl frame data</td><td>1196416</td><td>✔</td><td>TlvTypeKLFrameData</td></tr>
<tr><td>640</td><td>skype</td><td>1311136</td><td>✔</td><td>TlvTypeSkypeAudioMetaInfo</td></tr>
<tr><td>640</td><td>skype</td><td>1311376</td><td>✔</td><td>TlvTypeSkypeAudioRecording</td></tr>
<tr><td>640</td><td>skype</td><td>1311648</td><td>✔</td><td>TlvTypeSkypeTextRecording</td></tr>
<tr><td>640</td><td>skype</td><td>1311904</td><td>✔</td><td>TlvTypeSkypeFileMetaInfo</td></tr>
<tr><td>640</td><td>skype</td><td>1312144</td><td>✔</td><td>TlvTypeSkypeFileRecording</td></tr>
<tr><td>640</td><td>skype</td><td>1312416</td><td>✔</td><td>TlvTypeSkypeContactsRecording</td></tr>
<tr><td>640</td><td>skype</td><td>1312640</td><td>✔</td><td>TlvTypeSkypeContactsUserData</td></tr>
<tr><td>646</td><td>config skype</td><td>1323168</td><td>✔</td><td>TlvTypeGetSkypeConfigRequest</td></tr>
<tr><td>646</td><td>config skype</td><td>1323424</td><td>✔</td><td>TlvTypeSkypeConfigReply</td></tr>
<tr><td>646</td><td>config skype</td><td>1323680</td><td>✔</td><td>TlvTypeSetSkypeConfigRequest</td></tr>
<tr><td>646</td><td>config skype</td><td>1324336</td><td>✔</td><td>TlvTypeConfigSkypeAudioEnable</td></tr>
<tr><td>646</td><td>config skype</td><td>1324592</td><td>✔</td><td>TlvTypeConfigSkypeTextEnable</td></tr>
<tr><td>646</td><td>config skype</td><td>1324848</td><td>✔</td><td>TlvTypeConfigSkypeFileEnable</td></tr>
<tr><td>647</td><td>config contacts enable list skype</td><td>1325104</td><td>✔</td><td>TlvTypeConfigSkypeContactsListEnable</td></tr>
<tr><td>648</td><td>skype</td><td>1327232</td><td>✔</td><td>TlvTypeSkypeAudioEncodingType</td></tr>
<tr><td>648</td><td>skype</td><td>1327488</td><td>✔</td><td>TlvTypeSkypeLoggedInUserAccountName</td></tr>
<tr><td>648</td><td>skype</td><td>1327744</td><td>✔</td><td>TlvTypeSkypeConversationPartnerAccountName</td></tr>
<tr><td>648</td><td>skype</td><td>1328000</td><td>✔</td><td>TlvTypeSkypeConversationPartnerDisplayName</td></tr>
<tr><td>648</td><td>skype</td><td>1328256</td><td>✔</td><td>TlvTypeSkypeChatMembers</td></tr>
<tr><td>648</td><td>skype</td><td>1328512</td><td>✔</td><td>TlvTypeSkypeTextMessage</td></tr>
<tr><td>648</td><td>skype</td><td>1328768</td><td>✔</td><td>TlvTypeSkypeChatID</td></tr>
<tr><td>648</td><td>skype</td><td>1329024</td><td>✔</td><td>TlvTypeSkypeSenderAccountName</td></tr>
<tr><td>649</td><td>skype</td><td>1329280</td><td>✔</td><td>TlvTypeSkypeSenderDisplayName</td></tr>
<tr><td>649</td><td>skype</td><td>1329536</td><td>✔</td><td>TlvTypeSkypeIncoming</td></tr>
<tr><td>649</td><td>skype</td><td>1329792</td><td>✔</td><td>TlvTypeSkypeSessionType</td></tr>
<tr><td>704</td><td>changed file</td><td>1442208</td><td>✔</td><td>TlvTypeChangedFileMetaInfo</td></tr>
<tr><td>704</td><td>changed file</td><td>1442432</td><td>✔</td><td>TlvTypeChangedFileChangeTime</td></tr>
<tr><td>704</td><td>changed file</td><td>1442688</td><td>✔</td><td>TlvTypeChangedFileChangeEvent</td></tr>
<tr><td>704</td><td>changed file</td><td>1442960</td><td>✔</td><td>TlvTypeChangedFileRecording</td></tr>
<tr><td>710</td><td>config changed</td><td>1454240</td><td>✔</td><td>TlvTypeGetChangedConfigRequest</td></tr>
<tr><td>710</td><td>config changed</td><td>1454496</td><td>✔</td><td>TlvTypeChangedConfigReply</td></tr>
<tr><td>710</td><td>config changed</td><td>1454752</td><td>✔</td><td>TlvTypeSetChangedConfigRequest</td></tr>
<tr><td>710</td><td>config changed</td><td>1454912</td><td>✔</td><td>TlvTypeConfigChangedEvents</td></tr>
<tr><td>736</td><td></td><td>1507744</td><td>✔</td><td>TlvTypeAccessedFileMetaInfo</td></tr>
<tr><td>736</td><td></td><td>1507968</td><td>✔</td><td>TlvTypeAccessedFileAccessTime</td></tr>
<tr><td>736</td><td></td><td>1508224</td><td>✔</td><td>TlvTypeAccessedFileAccessEvent</td></tr>
<tr><td>736</td><td></td><td>1508496</td><td>✔</td><td>TlvTypeAccessedFileRecording</td></tr>
<tr><td>736</td><td></td><td>1508736</td><td>✔</td><td>TlvTypeAccessedApplicationName</td></tr>
<tr><td>736</td><td></td><td>1508912</td><td>✔</td><td>TlvTypeConfigRecordImagesFromExplorer</td></tr>
<tr><td>742</td><td>accessed config</td><td>1519776</td><td>✔</td><td>TlvTypeGetAccessedConfigRequest</td></tr>
<tr><td>742</td><td>accessed config</td><td>1520032</td><td>✔</td><td>TlvTypeAccessedConfigReply</td></tr>
<tr><td>742</td><td>accessed config</td><td>1520288</td><td>✔</td><td>TlvTypeSetAccessedConfigRequest</td></tr>
<tr><td>742</td><td>accessed config</td><td>1520448</td><td>✔</td><td>TlvTypeConfigAccessedEvents</td></tr>
<tr><td>768</td><td>print</td><td>1573280</td><td>✔</td><td>TlvTypePrintFileMetaInfo</td></tr>
<tr><td>768</td><td>print</td><td>1573520</td><td>✔</td><td>TlvTypePrintFrame</td></tr>
<tr><td>772</td><td>print</td><td>1581184</td><td>✔</td><td>TlvTypePrintApplicationName</td></tr>
<tr><td>772</td><td>print</td><td>1581440</td><td>✔</td><td>TlvTypePrintFilename</td></tr>
<tr><td>772</td><td>print</td><td>1581696</td><td>✔</td><td>TlvTypePrintEncodingType</td></tr>
<tr><td>774</td><td>print config</td><td>1585312</td><td>✔</td><td>TlvTypeGetPrintConfigRequest</td></tr>
<tr><td>774</td><td>print config</td><td>1585568</td><td>✔</td><td>TlvTypePrintConfigReply</td></tr>
<tr><td>774</td><td>print config</td><td>1585824</td><td>✔</td><td>TlvTypeSetPrintConfigRequest</td></tr>
<tr><td>800</td><td>deleted</td><td>1638816</td><td>✔</td><td>TlvTypeDeletedFileMetaInfo</td></tr>
<tr><td>800</td><td>deleted</td><td>1639296</td><td>✔</td><td>TlvTypeDeletedFileDeletionTime</td></tr>
<tr><td>800</td><td>deleted</td><td>1639552</td><td>✔</td><td>TlvTypeDeletedFileRecycleBin</td></tr>
<tr><td>800</td><td>deleted</td><td>1639808</td><td>✔</td><td>TlvTypeDeletedMethod</td></tr>
<tr><td>800</td><td>deleted</td><td>1640064</td><td>✔</td><td>TlvTypeDeletedApplicationName</td></tr>
<tr><td>800</td><td>deleted</td><td>1640336</td><td>✔</td><td>TlvTypeDeletedFileRecording</td></tr>
<tr><td>806</td><td>config deleted</td><td>1650848</td><td>✔</td><td>TlvTypeGetDeletedConfigRequest</td></tr>
<tr><td>806</td><td>config deleted</td><td>1651104</td><td>✔</td><td>TlvTypeDeletedConfigReply</td></tr>
<tr><td>806</td><td>config deleted</td><td>1651360</td><td>✔</td><td>TlvTypeSetDeletedConfigRequest</td></tr>
<tr><td>1024</td><td>application upload forensics</td><td>2097568</td><td>✔</td><td>TlvTypeUploadForensicsApplicationRequest</td></tr>
<tr><td>1024</td><td>application upload forensics</td><td>2097824</td><td>✔</td><td>TlvTypeUploadForensicsApplicationReply</td></tr>
<tr><td>1024</td><td>application upload forensics</td><td>2098080</td><td>✔</td><td>TlvTypeUploadForensicsApplicationChunk</td></tr>
<tr><td>1024</td><td>application upload forensics</td><td>2098336</td><td>✔</td><td>TlvTypeUploadForensicsApplicationDoneRequest</td></tr>
<tr><td>1024</td><td>application upload forensics</td><td>2098592</td><td>✔</td><td>TlvTypeUploadForensicsApplicationDoneReply</td></tr>
<tr><td>1026</td><td>application remove forensics</td><td>2101664</td><td>✔</td><td>TlvTypeRemoveForensicsApplicationRequest</td></tr>
<tr><td>1026</td><td>application remove forensics</td><td>2101920</td><td>✔</td><td>TlvTypeRemoveForensicsApplicationReply</td></tr>
<tr><td>1028</td><td>app forensics execute</td><td>2105760</td><td>✔</td><td>TlvTypeForensicsAppExecuteRequest</td></tr>
<tr><td>1028</td><td>app forensics execute</td><td>2106016</td><td>✔</td><td>TlvTypeForensicsAppExecuteReply</td></tr>
<tr><td>1028</td><td>app forensics execute</td><td>2106272</td><td>✔</td><td>TlvTypeForensicsAppExecuteResult</td></tr>
<tr><td>1028</td><td>app forensics execute</td><td>2106528</td><td>✔</td><td>TlvTypeForensicsAppExecuteResultChunk</td></tr>
<tr><td>1028</td><td>app forensics execute</td><td>2106784</td><td>✔</td><td>TlvTypeForensicsAppExecuteResultDone</td></tr>
<tr><td>1028</td><td>app forensics execute</td><td>2107040</td><td>✔</td><td>TlvTypeForensicsCancelAppExecuteRequest</td></tr>
<tr><td>1028</td><td>app forensics execute</td><td>2107296</td><td>✔</td><td>TlvTypeForensicsCancelAppExecuteReply</td></tr>
<tr><td>1030</td><td>config forensics</td><td>2109600</td><td>✔</td><td>TlvTypeGetForensicsConfigRequest</td></tr>
<tr><td>1030</td><td>config forensics</td><td>2109856</td><td>✔</td><td>TlvTypeForensicsConfigReply</td></tr>
<tr><td>1030</td><td>config forensics</td><td>2110112</td><td>✔</td><td>TlvTypeSetForensicsConfigRequest</td></tr>
<tr><td>1032</td><td>application config info forensics</td><td>2113680</td><td>✔</td><td>TlvTypeConfigForensicsApplicationInfoGeneric</td></tr>
<tr><td>1032</td><td>application config info forensics</td><td>2113952</td><td>✔</td><td>TlvTypeConfigForensicsApplicationInfo</td></tr>
<tr><td>1034</td><td>forensics</td><td>2117760</td><td>✔</td><td>TlvTypeConfigForensicsApplicationName</td></tr>
<tr><td>1034</td><td>forensics</td><td>2117952</td><td>✔</td><td>TlvTypeConfigForensicsApplicationSize</td></tr>
<tr><td>1034</td><td>forensics</td><td>2118208</td><td>✔</td><td>TlvTypeConfigForensicsApplicationID</td></tr>
<tr><td>1034</td><td>forensics</td><td>2118528</td><td>✔</td><td>TlvTypeConfigForensicsApplicationCmdline</td></tr>
<tr><td>1034</td><td>forensics</td><td>2118784</td><td>✔</td><td>TlvTypeConfigForensicsApplicationOutput</td></tr>
<tr><td>1034</td><td>forensics</td><td>2118976</td><td>✔</td><td>TlvTypeConfigForensicsApplicationTimeout</td></tr>
<tr><td>1034</td><td>forensics</td><td>2119232</td><td>✔</td><td>TlvTypeConfigForensicsApplicationVersion</td></tr>
<tr><td>1034</td><td>forensics</td><td>2119552</td><td>✔</td><td>TlvTypeForensicsFriendlyName</td></tr>
<tr><td>1035</td><td>output application config forensics</td><td>2119808</td><td>✔</td><td>TlvTypeConfigForensicsApplicationOutputPrepend</td></tr>
<tr><td>1035</td><td>output application config forensics</td><td>2120064</td><td>✔</td><td>TlvTypeConfigForensicsApplicationOutputContentType</td></tr>
<tr><td>1056</td><td>vo meta info ip</td><td>2163104</td><td>✔</td><td>TlvTypeVoIPMetaInfo</td></tr>
<tr><td>1058</td><td>vo ip</td><td>2166912</td><td>✔</td><td>TlvTypeVoIPEncodingType</td></tr>
<tr><td>1058</td><td>vo ip</td><td>2167168</td><td>✔</td><td>TlvTypeVoIPSessionType</td></tr>
<tr><td>1058</td><td>vo ip</td><td>2167424</td><td>✔</td><td>TlvTypeVoIPApplicationName</td></tr>
<tr><td>1058</td><td>vo ip</td><td>2167696</td><td>✔</td><td>TlvTypeVoIPAppScreenshot</td></tr>
<tr><td>1058</td><td>vo ip</td><td>2167952</td><td>✔</td><td>TlvTypeVoIPAudioRecording</td></tr>
<tr><td>1058</td><td>vo ip</td><td>2168112</td><td>✔</td><td>TlvTypeConfigVoIPScreenshotEnabled</td></tr>
<tr><td>1062</td><td>vo config ip</td><td>2175136</td><td>✔</td><td>TlvTypeGetVoIPConfigRequest</td></tr>
<tr><td>1062</td><td>vo config ip</td><td>2175392</td><td>✔</td><td>TlvTypeVoIPConfigReply</td></tr>
<tr><td>1062</td><td>vo config ip</td><td>2175648</td><td>✔</td><td>TlvTypeSetVoIPConfigRequest</td></tr>
<tr><td>1088</td><td>clicks mouse</td><td>2228640</td><td>✔</td><td>TlvTypeMouseClicksMetaInfo</td></tr>
<tr><td>1088</td><td>clicks mouse</td><td>2228896</td><td>✔</td><td>TlvTypeMouseClicksFrame</td></tr>
<tr><td>1090</td><td>clicks mouse</td><td>2232448</td><td>✔</td><td>TlvTypeMouseClicksEncodingType</td></tr>
<tr><td>1090</td><td>clicks mouse</td><td>2232896</td><td>✔</td><td>TlvTypeConfigMouseClicksRectangle</td></tr>
<tr><td>1090</td><td>clicks mouse</td><td>2233152</td><td>✔</td><td>TlvTypeConfigMouseClicksSensitivity</td></tr>
<tr><td>1090</td><td>clicks mouse</td><td>2233408</td><td>✔</td><td>TlvTypeConfigMouseClicksType</td></tr>
<tr><td>1094</td><td>clicks config mouse</td><td>2240672</td><td>✔</td><td>TlvTypeGetMouseClicksConfigRequest</td></tr>
<tr><td>1094</td><td>clicks config mouse</td><td>2240928</td><td>✔</td><td>TlvTypeMouseClicksConfigReply</td></tr>
<tr><td>1094</td><td>clicks config mouse</td><td>2241184</td><td>✔</td><td>TlvTypeSetMouseClicksConfigRequest</td></tr>
<tr><td>2112</td><td>sms</td><td>4325792</td><td>✔</td><td>TlvTypeMobileSMSMetaInfo</td></tr>
<tr><td>2112</td><td>sms</td><td>4326016</td><td>✔</td><td>TlvTypeMobileSMSData</td></tr>
<tr><td>2112</td><td>sms</td><td>4326256</td><td>✔</td><td>TlvTypeSMSSenderNumber</td></tr>
<tr><td>2112</td><td>sms</td><td>4326512</td><td>✔</td><td>TlvTypeSMSRecipientNumber</td></tr>
<tr><td>2112</td><td>sms</td><td>4326528</td><td>✔</td><td>TlvTypeSMSInformation</td></tr>
<tr><td>2112</td><td>sms</td><td>4326768</td><td>✔</td><td>TlvTypeSMSDirection</td></tr>
<tr><td>2112</td><td>sms</td><td>4327040</td><td>×</td><td>unknown</td></tr>
<tr><td>2144</td><td>address book mobile</td><td>4391328</td><td>✔</td><td>TlvTypeMobileAddressBookMetaInfo</td></tr>
<tr><td>2144</td><td>address book mobile</td><td>4391552</td><td>✔</td><td>TlvTypeMobileAddressBookData</td></tr>
<tr><td>2152</td><td>address book checksum mobile</td><td>4407360</td><td>✔</td><td>TlvTypeMobileAddressBookChecksum</td></tr>
<tr><td>2176</td><td>mobile blackberry</td><td>4456864</td><td>✔</td><td>TlvTypeMobileBlackberryMessengerMetaInfo</td></tr>
<tr><td>2176</td><td>mobile blackberry</td><td>4457088</td><td>✔</td><td>TlvTypeMobileBlackberryMessengerData</td></tr>
<tr><td>2176</td><td>mobile blackberry</td><td>4457328</td><td>✔</td><td>TlvTypeMobileBlackberryMsChatID</td></tr>
<tr><td>2176</td><td>mobile blackberry</td><td>4457600</td><td>✔</td><td>TlvTypeMobileBlackberryMsConversationPartners</td></tr>
<tr><td>2208</td><td>mobile tracking</td><td>4522400</td><td>✔</td><td>TlvTypeMobileTrackingStartRequest</td></tr>
<tr><td>2208</td><td>mobile tracking</td><td>4522656</td><td>✔</td><td>TlvTypeMobileTrackingStopRequest</td></tr>
<tr><td>2208</td><td>mobile tracking</td><td>4523376</td><td>✔</td><td>TlvTypeMobileTrackingDataV10</td></tr>
<tr><td>2214</td><td>mobile config tracking</td><td>4535200</td><td>✔</td><td>TlvTypeMobileTrackingConfig</td></tr>
<tr><td>2214</td><td>mobile config tracking</td><td>4535440</td><td>✔</td><td>TlvTypeMobileTrackingConfigRaw</td></tr>
<tr><td>2216</td><td>mobile tracking</td><td>4538432</td><td>✔</td><td>TlvTypeMobileTrackingTimeInterval</td></tr>
<tr><td>2216</td><td>mobile tracking</td><td>4538688</td><td>✔</td><td>TlvTypeMobileTrackingDistance</td></tr>
<tr><td>2216</td><td>mobile tracking</td><td>4538928</td><td>✔</td><td>TlvTypeMobileTrackingSendOnAnyChannel</td></tr>
<tr><td>2240</td><td>mobile call phone</td><td>4587936</td><td>✔</td><td>TlvTypeMobilePhoneCallLogsMetaInfo</td></tr>
<tr><td>2240</td><td>mobile call phone</td><td>4588192</td><td>✔</td><td>TlvTypeMobilePhoneCallLogsData</td></tr>
<tr><td>2240</td><td>mobile call phone</td><td>4588400</td><td>✔</td><td>TlvTypeMobilePhoneCallLogsType</td></tr>
<tr><td>2240</td><td>mobile call phone</td><td>4588672</td><td>✔</td><td>TlvTypeMobilePhoneCallAdditionalInformation</td></tr>
<tr><td>2240</td><td>mobile call phone</td><td>4588912</td><td>✔</td><td>TlvTypeMobilePhoneCallLogsCallerNumber</td></tr>
<tr><td>2240</td><td>mobile call phone</td><td>4589168</td><td>✔</td><td>TlvTypeMobilePhoneCallLogsCalleeNumber</td></tr>
<tr><td>2240</td><td>mobile call phone</td><td>4589440</td><td>✔</td><td>TlvTypeMobilePhoneCallLogsCallerName</td></tr>
<tr><td>2241</td><td>name call phone logs mobile callee</td><td>4589696</td><td>✔</td><td>TlvTypeMobilePhoneCallLogsCalleeName</td></tr>
<tr><td>2242</td><td>last call phone entry mobile endtime log</td><td>4591680</td><td>✔</td><td>TlvTypeMobilePhoneCallLogLastEntryEndtime</td></tr>
<tr><td>3072</td><td>mobile logging</td><td>6291872</td><td>✔</td><td>TlvTypeMobileLoggingMetaInfo</td></tr>
<tr><td>3072</td><td>mobile logging</td><td>6292096</td><td>✔</td><td>TlvTypeMobileLoggingData</td></tr>
<tr><td>3616</td><td>master agent</td><td>7405984</td><td>✔</td><td>TlvTypeMasterAgentLogin</td></tr>
<tr><td>3616</td><td>master agent</td><td>7406240</td><td>✔</td><td>TlvTypeMasterAgentLoginAnswer</td></tr>
<tr><td>3616</td><td>master agent</td><td>7406752</td><td>✔</td><td>TlvTypeMasterAgentTargetList</td></tr>
<tr><td>3616</td><td>master agent</td><td>7407008</td><td>✔</td><td>TlvTypeMasterAgentTargetOnlineList</td></tr>
<tr><td>3616</td><td>master agent</td><td>7407264</td><td>✔</td><td>TlvTypeMasterAgentTargetInfoReply</td></tr>
<tr><td>3616</td><td>master agent</td><td>7407520</td><td>✔</td><td>TlvTypeMasterAgentUserList</td></tr>
<tr><td>3617</td><td>master agent list</td><td>7407776</td><td>✔</td><td>TlvTypeMasterAgentUserListReply</td></tr>
<tr><td>3617</td><td>master agent list</td><td>7408032</td><td>✔</td><td>TlvTypeMasterAgentTargetArchivedList</td></tr>
<tr><td>3617</td><td>master agent list</td><td>7408288</td><td>✔</td><td>TlvTypeMasterAgentTargetListEx</td></tr>
<tr><td>3617</td><td>master agent list</td><td>7408544</td><td>✔</td><td>TlvTypeMasterAgentTargetOnlineListEx</td></tr>
<tr><td>3617</td><td>master agent list</td><td>7408800</td><td>✔</td><td>TlvTypeMasterAgentMobileTargetArchivedList</td></tr>
<tr><td>3617</td><td>master agent list</td><td>7409056</td><td>✔</td><td>TlvTypeMasterAgentMobileTargetList</td></tr>
<tr><td>3617</td><td>master agent list</td><td>7409312</td><td>✔</td><td>TlvTypeMasterAgentMobileTargetOnlineList</td></tr>
<tr><td>3618</td><td></td><td>7409824</td><td>✔</td><td>TlvTypeMasterAgentQueryFirst</td></tr>
<tr><td>3618</td><td></td><td>7410080</td><td>✔</td><td>TlvTypeMasterAgentQueryNext</td></tr>
<tr><td>3618</td><td></td><td>7410336</td><td>✔</td><td>TlvTypeMasterAgentQueryLast</td></tr>
<tr><td>3618</td><td></td><td>7410592</td><td>✔</td><td>TlvTypeMasterAgentQueryAnswer</td></tr>
<tr><td>3618</td><td></td><td>7410848</td><td>✔</td><td>TlvTypeMasterAgentRemoveRecord</td></tr>
<tr><td>3618</td><td></td><td>7411104</td><td>✔</td><td>TlvTypeMasterAgentTargetInfoExReply</td></tr>
<tr><td>3618</td><td></td><td>7411344</td><td>✔</td><td>TlvTypeTargetInfoExProperty</td></tr>
<tr><td>3618</td><td></td><td>7411616</td><td>✔</td><td>TlvTypeTargetInfoExPropertyValue</td></tr>
<tr><td>3619</td><td></td><td>7411840</td><td>✔</td><td>TlvTypeTargetInfoExPropertyValueName</td></tr>
<tr><td>3619</td><td></td><td>7411968</td><td>✔</td><td>TlvTypeTargetInfoExPropertyValueData</td></tr>
<tr><td>3619</td><td></td><td>7412384</td><td>✔</td><td>TlvTypeMasterAgentAlarm</td></tr>
<tr><td>3620</td><td>master agent</td><td>7413920</td><td>✔</td><td>TlvTypeMasterAgentRetrieveData</td></tr>
<tr><td>3620</td><td>master agent</td><td>7414176</td><td>✔</td><td>TlvTypeMasterAgentRetrieveDataAnswer</td></tr>
<tr><td>3620</td><td>master agent</td><td>7414432</td><td>✔</td><td>TlvTypeMasterAgentRemoveUser</td></tr>
<tr><td>3620</td><td>master agent</td><td>7414688</td><td>✔</td><td>TlvTypeMasterAgentRemoveTarget</td></tr>
<tr><td>3620</td><td>master agent</td><td>7414944</td><td>✔</td><td>TlvTypeMasterAgentRetrieveDataComments</td></tr>
<tr><td>3620</td><td>master agent</td><td>7415200</td><td>✔</td><td>TlvTypeMasterAgentUpdateDataComments</td></tr>
<tr><td>3620</td><td>master agent</td><td>7415712</td><td>✔</td><td>TlvTypeMasterAgentRetrieveActivityLogging</td></tr>
<tr><td>3621</td><td>master agent</td><td>7415968</td><td>✔</td><td>TlvTypeMasterAgentRetrieveMasterLogging</td></tr>
<tr><td>3621</td><td>master agent</td><td>7416224</td><td>✔</td><td>TlvTypeMasterAgentRetrieveAgentActivityLogging</td></tr>
<tr><td>3621</td><td>master agent</td><td>7417248</td><td>✔</td><td>TlvTypeMasterAgentSendUserGUIConfig</td></tr>
<tr><td>3621</td><td>master agent</td><td>7417504</td><td>✔</td><td>TlvTypeMasterAgentGetUserGUIConfigRequest</td></tr>
<tr><td>3621</td><td>master agent</td><td>7417760</td><td>✔</td><td>TlvTypeMasterAgentGetUserGUIConfigReply</td></tr>
<tr><td>3622</td><td>master agent</td><td>7418016</td><td>✔</td><td>TlvTypeMasterAgentProxyList</td></tr>
<tr><td>3622</td><td>master agent</td><td>7418272</td><td>✔</td><td>TlvTypeMasterAgentProxyInfoReply</td></tr>
<tr><td>3622</td><td>master agent</td><td>7419040</td><td>✔</td><td>TlvTypeMasterAgentNameValuePacket</td></tr>
<tr><td>3622</td><td>master agent</td><td>7419248</td><td>✔</td><td>TlvTypeMasterAgentValueName</td></tr>
<tr><td>3622</td><td>master agent</td><td>7419392</td><td>✔</td><td>TlvTypeMasterAgentValueData</td></tr>
<tr><td>3622</td><td>master agent</td><td>7419808</td><td>✔</td><td>TlvTypeMasterAgentRetrieveTargetHistory</td></tr>
<tr><td>3623</td><td>install master agent</td><td>7421088</td><td>✔</td><td>TlvTypeMasterAgentInstallMasterLicense</td></tr>
<tr><td>3623</td><td>install master agent</td><td>7421344</td><td>✔</td><td>TlvTypeMasterAgentInstallSoftwareUpdate</td></tr>
<tr><td>3623</td><td>install master agent</td><td>7421600</td><td>✔</td><td>TlvTypeMasterAgentInstallSoftwareUpdateChunk</td></tr>
<tr><td>3623</td><td>install master agent</td><td>7421856</td><td>✔</td><td>TlvTypeMasterAgentInstallSoftwareUpdateDone</td></tr>
<tr><td>3624</td><td>master agent</td><td>7422112</td><td>✔</td><td>TlvTypeMasterAgentSoftwareUpdateInfo</td></tr>
<tr><td>3624</td><td>master agent</td><td>7422368</td><td>✔</td><td>TlvTypeMasterAgentSoftwareUpdateInfoReply</td></tr>
<tr><td>3624</td><td>master agent</td><td>7422624</td><td>✔</td><td>TlvTypeMasterAgentSoftwareUpdate</td></tr>
<tr><td>3624</td><td>master agent</td><td>7422880</td><td>✔</td><td>TlvTypeMasterAgentSoftwareUpdateReply</td></tr>
<tr><td>3624</td><td>master agent</td><td>7423136</td><td>✔</td><td>TlvTypeMasterAgentSoftwareUpdateNext</td></tr>
<tr><td>3624</td><td>master agent</td><td>7423392</td><td>✔</td><td>TlvTypeMasterAgentAddTimeSchedule</td></tr>
<tr><td>3624</td><td>master agent</td><td>7423648</td><td>✔</td><td>TlvTypeMasterAgentAddScreenSchedule</td></tr>
<tr><td>3624</td><td>master agent</td><td>7423904</td><td>✔</td><td>TlvTypeMasterAgentAddLockedSchedule</td></tr>
<tr><td>3625</td><td>master agent</td><td>7424160</td><td>✔</td><td>TlvTypeMasterAgentRemoveSchedule</td></tr>
<tr><td>3625</td><td>master agent</td><td>7424416</td><td>✔</td><td>TlvTypeMasterAgentGetSchedulerList</td></tr>
<tr><td>3625</td><td>master agent</td><td>7424672</td><td>✔</td><td>TlvTypeMasterAgentSchedulerTimeAction</td></tr>
<tr><td>3625</td><td>master agent</td><td>7424928</td><td>✔</td><td>TlvTypeMasterAgentSchedulerScreenAction</td></tr>
<tr><td>3625</td><td>master agent</td><td>7425184</td><td>✔</td><td>TlvTypeMasterAgentSchedulerLockedAction</td></tr>
<tr><td>3625</td><td>master agent</td><td>7425440</td><td>✔</td><td>TlvTypeMasterAgentProjectSoftwareUpdateInfo</td></tr>
<tr><td>3625</td><td>master agent</td><td>7425696</td><td>✔</td><td>TlvTypeMasterAgentProjectSoftwareUpdateInfoReply</td></tr>
<tr><td>3625</td><td>master agent</td><td>7425952</td><td>✔</td><td>TlvTypeMasterAgentProjectSoftwareUpdate</td></tr>
<tr><td>3626</td><td>master agent</td><td>7426112</td><td>✔</td><td>TlvTypeMasterAgentSchedulerID</td></tr>
<tr><td>3626</td><td>master agent</td><td>7426368</td><td>✔</td><td>TlvTypeMasterAgentSchedulerStartTime</td></tr>
<tr><td>3626</td><td>master agent</td><td>7426624</td><td>✔</td><td>TlvTypeMasterAgentSchedulerStopTime</td></tr>
<tr><td>3626</td><td>master agent</td><td>7427488</td><td>✔</td><td>TlvTypeMasterAgentAddRecordedDataAvailableSchedule</td></tr>
<tr><td>3626</td><td>master agent</td><td>7427744</td><td>✔</td><td>TlvTypeMasterAgentSchedulerRecordedDataAvailableAction</td></tr>
<tr><td>3627</td><td>master agent data</td><td>7428256</td><td>✔</td><td>TlvTypeMasterAgentRetrieveRemoteMasterData</td></tr>
<tr><td>3627</td><td>master agent data</td><td>7428512</td><td>✔</td><td>TlvTypeMasterAgentRetrieveRemoteMasterDataReply</td></tr>
<tr><td>3627</td><td>master agent data</td><td>7428768</td><td>✔</td><td>TlvTypeMasterAgentDeleteRemoteMasterData</td></tr>
<tr><td>3627</td><td>master agent data</td><td>7429024</td><td>✔</td><td>TlvTypeMasterAgentRetrieveOfflineMasterData</td></tr>
<tr><td>3627</td><td>master agent data</td><td>7429280</td><td>✔</td><td>TlvTypeMasterAgentRetrieveOfflineMasterDataReply</td></tr>
<tr><td>3627</td><td>master agent data</td><td>7429536</td><td>✔</td><td>TlvTypeMasterAgentDeleteOfflineMasterData</td></tr>
<tr><td>3628</td><td>master agent</td><td>7430304</td><td>✔</td><td>TlvTypeMasterAgentQueryFirstEx</td></tr>
<tr><td>3628</td><td>master agent</td><td>7430560</td><td>✔</td><td>TlvTypeMasterAgentQueryNextEx</td></tr>
<tr><td>3628</td><td>master agent</td><td>7430816</td><td>✔</td><td>TlvTypeMasterAgentQueryLastEx</td></tr>
<tr><td>3628</td><td>master agent</td><td>7431072</td><td>✔</td><td>TlvTypeMasterAgentQueryAnswerEx</td></tr>
<tr><td>3628</td><td>master agent</td><td>7431328</td><td>✔</td><td>TlvTypeMasterAgentSendUserPreferences</td></tr>
<tr><td>3628</td><td>master agent</td><td>7431584</td><td>✔</td><td>TlvTypeMasterAgentGetUserPreferencesRequest</td></tr>
<tr><td>3628</td><td>master agent</td><td>7431840</td><td>✔</td><td>TlvTypeMasterAgentGetUserPreferencesReply</td></tr>
<tr><td>3628</td><td>master agent</td><td>7432096</td><td>✔</td><td>TlvTypeMasterAgentListMCFilesRequest</td></tr>
<tr><td>3629</td><td>master agent mc</td><td>7432608</td><td>✔</td><td>TlvTypeMasterAgentDeleteMCFiles</td></tr>
<tr><td>3629</td><td>master agent mc</td><td>7432864</td><td>✔</td><td>TlvTypeMasterAgentSendMCFiles</td></tr>
<tr><td>3629</td><td>master agent mc</td><td>7433120</td><td>✔</td><td>TlvTypeMasterAgentMCStatisticsRequest</td></tr>
<tr><td>3629</td><td>master agent mc</td><td>7433376</td><td>✔</td><td>TlvTypeMasterAgentMCStatisticsReply</td></tr>
<tr><td>3629</td><td>master agent mc</td><td>7433616</td><td>✔</td><td>TlvTypeMasterAgentMCStatisticsValues</td></tr>
<tr><td>3630</td><td>master agent</td><td>7434400</td><td>✔</td><td>TlvTypeMasterAgentTrojanKeyRequest</td></tr>
<tr><td>3630</td><td>master agent</td><td>7434656</td><td>✔</td><td>TlvTypeMasterAgentTrojanKeyReply</td></tr>
<tr><td>3630</td><td>master agent</td><td>7434912</td><td>✔</td><td>TlvTypeMasterAgentEvProtectionX509Request</td></tr>
<tr><td>3630</td><td>master agent</td><td>7435168</td><td>✔</td><td>TlvTypeMasterAgentEvProtectionX509Reply</td></tr>
<tr><td>3630</td><td>master agent</td><td>7435424</td><td>✔</td><td>TlvTypeMasterAgentEvProtectionImportCert</td></tr>
<tr><td>3630</td><td>master agent</td><td>7435680</td><td>✔</td><td>TlvTypeMasterAgentEvProtectionImportCertCompleted</td></tr>
<tr><td>3630</td><td>master agent</td><td>7435936</td><td>✔</td><td>TlvTypeMasterAgentConfigurationRequest</td></tr>
<tr><td>3630</td><td>master agent</td><td>7436192</td><td>✔</td><td>TlvTypeMasterAgentConfigurationReply</td></tr>
<tr><td>3631</td><td>master agent configuration</td><td>7436448</td><td>✔</td><td>TlvTypeMasterAgentConfigurationUpdateRequest</td></tr>
<tr><td>3631</td><td>master agent configuration</td><td>7436704</td><td>✔</td><td>TlvTypeMasterAgentConfigurationUpdateRequestCompleted</td></tr>
<tr><td>3631</td><td>master agent configuration</td><td>7436944</td><td>✔</td><td>TlvTypeMasterAgentConfiguration</td></tr>
<tr><td>3631</td><td>master agent configuration</td><td>7437216</td><td>✔</td><td>TlvTypeMasterAgentConfigurationValue</td></tr>
<tr><td>3631</td><td>master agent configuration</td><td>7437424</td><td>✔</td><td>TlvTypeMasterAgentConfigurationValueName</td></tr>
<tr><td>3631</td><td>master agent configuration</td><td>7437568</td><td>✔</td><td>TlvTypeMasterAgentConfigurationValueData</td></tr>
<tr><td>3631</td><td>master agent configuration</td><td>7437984</td><td>✔</td><td>TlvTypeMasterAgentConfigurationTransferDone</td></tr>
<tr><td>3632</td><td>master agent</td><td>7438496</td><td>✔</td><td>TlvTypeMasterAgentRetrieveTargetFile</td></tr>
<tr><td>3632</td><td>master agent</td><td>7438752</td><td>✔</td><td>TlvTypeMasterAgentRetrieveTargetFileAnswer</td></tr>
<tr><td>3632</td><td>master agent</td><td>7438912</td><td>✔</td><td>TlvTypeMasterAgentAlarmEntryID</td></tr>
<tr><td>3632</td><td>master agent</td><td>7439168</td><td>✔</td><td>TlvTypeMasterAgentAlarmEntryVersion</td></tr>
<tr><td>3632</td><td>master agent</td><td>7439424</td><td>✔</td><td>TlvTypeMasterAgentAlarmTriggerFlags</td></tr>
<tr><td>3632</td><td>master agent</td><td>7439776</td><td>✔</td><td>TlvTypeMasterAgentGetAlarmList</td></tr>
<tr><td>3632</td><td>master agent</td><td>7440032</td><td>✔</td><td>TlvTypeMasterAgentAddAlarmEntry</td></tr>
<tr><td>3632</td><td>master agent</td><td>7440288</td><td>✔</td><td>TlvTypeMasterAgentRemoveAlarmEntry</td></tr>
<tr><td>3633</td><td>master agent</td><td>7440544</td><td>✔</td><td>TlvTypeMasterAgentAlarmEntry</td></tr>
<tr><td>3633</td><td>master agent</td><td>7440800</td><td>✔</td><td>TlvTypeMasterAgentSystemStatus</td></tr>
<tr><td>3633</td><td>master agent</td><td>7441056</td><td>✔</td><td>TlvTypeMasterAgentSystemStatusRequest</td></tr>
<tr><td>3633</td><td>master agent</td><td>7441312</td><td>✔</td><td>TlvTypeMasterAgentSystemStatusReply</td></tr>
<tr><td>3633</td><td>master agent</td><td>7441552</td><td>✔</td><td>TlvTypeMasterAgentLicenseValues</td></tr>
<tr><td>3633</td><td>master agent</td><td>7441824</td><td>✔</td><td>TlvTypeMasterAgentLicenseValuesRequest</td></tr>
<tr><td>3633</td><td>master agent</td><td>7442080</td><td>✔</td><td>TlvTypeMasterAgentLicenseValuesReply</td></tr>
<tr><td>3634</td><td>master agent</td><td>7442592</td><td>✔</td><td>TlvTypeMasterAgentGetNetworkConfigurationRequest</td></tr>
<tr><td>3634</td><td>master agent</td><td>7442848</td><td>✔</td><td>TlvTypeMasterAgentSetNetworkConfigurationRequest</td></tr>
<tr><td>3634</td><td>master agent</td><td>7443104</td><td>✔</td><td>TlvTypeMasterAgentSetNetworkConfigurationReply</td></tr>
<tr><td>3634</td><td>master agent</td><td>7443360</td><td>✔</td><td>TlvTypeMasterAgentRetrieveAllowedModulesList</td></tr>
<tr><td>3634</td><td>master agent</td><td>7443616</td><td>✔</td><td>TlvTypeMasterAgentRetrieveAllowedModulesListAnswer</td></tr>
<tr><td>3636</td><td>master agent</td><td>7446688</td><td>✔</td><td>TlvTypeMasterAgentRemoveAllTargetData</td></tr>
<tr><td>3636</td><td>master agent</td><td>7446944</td><td>✔</td><td>TlvTypeMasterAgentForceDownloadRecordedData</td></tr>
<tr><td>3636</td><td>master agent</td><td>7447200</td><td>✔</td><td>TlvTypeMasterAgentTargetCreateNotification</td></tr>
<tr><td>3636</td><td>master agent</td><td>7447456</td><td>✔</td><td>TlvTypeMasterAgentMobileTargetInfoReply</td></tr>
<tr><td>3636</td><td>master agent</td><td>7447696</td><td>✔</td><td>TlvTypeMasterAgentMobileTargetInfoValues</td></tr>
<tr><td>3638</td><td>master agent alert</td><td>7450784</td><td>✔</td><td>TlvTypeMasterAgentAlert</td></tr>
<tr><td>3640</td><td>master agent</td><td>7454880</td><td>✔</td><td>TlvTypeMasterAgentAddUser</td></tr>
<tr><td>3640</td><td>master agent</td><td>7455392</td><td>✔</td><td>TlvTypeMasterAgentAddUserReply</td></tr>
<tr><td>3640</td><td>master agent</td><td>7455648</td><td>✔</td><td>TlvTypeMasterAgentModifyUser</td></tr>
<tr><td>3640</td><td>master agent</td><td>7455904</td><td>✔</td><td>TlvTypeMasterAgentSetUserPermission</td></tr>
<tr><td>3640</td><td>master agent</td><td>7456160</td><td>✔</td><td>TlvTypeMasterAgentSetTargetPermission</td></tr>
<tr><td>3640</td><td>master agent</td><td>7456400</td><td>✔</td><td>TlvTypeMasterAgentUserPermission</td></tr>
<tr><td>3640</td><td>master agent</td><td>7456656</td><td>✔</td><td>TlvTypeMasterAgentTargetPermission</td></tr>
<tr><td>3641</td><td>master agent</td><td>7456928</td><td>✔</td><td>TlvTypeMasterAgentUserPermissionValuePacket</td></tr>
<tr><td>3641</td><td>master agent</td><td>7457184</td><td>✔</td><td>TlvTypeMasterAgentTargetPermissionValuePacket</td></tr>
<tr><td>3641</td><td>master agent</td><td>7457344</td><td>✔</td><td>TlvTypeMasterAgentUserPermissionValueName</td></tr>
<tr><td>3641</td><td>master agent</td><td>7457600</td><td>✔</td><td>TlvTypeMasterAgentTargetPermissionValueName</td></tr>
<tr><td>3641</td><td>master agent</td><td>7457856</td><td>✔</td><td>TlvTypeMasterAgentUserPermissionValueData</td></tr>
<tr><td>3641</td><td>master agent</td><td>7458112</td><td>✔</td><td>TlvTypeMasterAgentTargetPermissionValueData</td></tr>
<tr><td>3641</td><td>master agent</td><td>7458464</td><td>✔</td><td>TlvTypeMasterAgentModifyPassword</td></tr>
<tr><td>3641</td><td>master agent</td><td>7458656</td><td>✔</td><td>TlvTypeMasterAgentMobileTargetPermissionValueName</td></tr>
<tr><td>3642</td><td>master agent</td><td>7458976</td><td>✔</td><td>TlvTypeMasterAgentUploadFile</td></tr>
<tr><td>3642</td><td>master agent</td><td>7459232</td><td>✔</td><td>TlvTypeMasterAgentUploadFileChunk</td></tr>
<tr><td>3642</td><td>master agent</td><td>7459488</td><td>✔</td><td>TlvTypeMasterAgentUploadFileDone</td></tr>
<tr><td>3642</td><td>master agent</td><td>7459744</td><td>✔</td><td>TlvTypeMasterAgentUploadFilesTransferDone</td></tr>
<tr><td>3642</td><td>master agent</td><td>7460000</td><td>✔</td><td>TlvTypeMasterAgentGetTargetModuleConfigRequest</td></tr>
<tr><td>3642</td><td>master agent</td><td>7460256</td><td>✔</td><td>TlvTypeMasterAgentRemoveFile</td></tr>
<tr><td>3642</td><td>master agent</td><td>7460512</td><td>✔</td><td>TlvTypeMasterAgentMobileProxyList</td></tr>
<tr><td>3642</td><td>master agent</td><td>7460768</td><td>✔</td><td>TlvTypeMasterAgentSMSProxyList</td></tr>
<tr><td>3643</td><td>master agent</td><td>7461024</td><td>✔</td><td>TlvTypeMasterAgentSMSProxyInfoReply</td></tr>
<tr><td>3643</td><td>master agent</td><td>7461280</td><td>✔</td><td>TlvTypeMasterAgentCallPhoneNumberList</td></tr>
<tr><td>3643</td><td>master agent</td><td>7461536</td><td>✔</td><td>TlvTypeMasterAgentCallPhoneNumberInfoReply</td></tr>
<tr><td>3643</td><td>master agent</td><td>7461792</td><td>✔</td><td>TlvTypeMasterAgentGetMobileTargetModuleConfigRequest</td></tr>
<tr><td>3643</td><td>master agent</td><td>7462048</td><td>✔</td><td>TlvTypeMasterAgentSendSMS</td></tr>
<tr><td>3647</td><td>master agent</td><td>7469984</td><td>✔</td><td>TlvTypeMasterAgentEncryptionRequired</td></tr>
<tr><td>3647</td><td>master agent</td><td>7470240</td><td>✔</td><td>TlvTypeMasterAgentFileCompleted</td></tr>
<tr><td>3647</td><td>master agent</td><td>7470496</td><td>✔</td><td>TlvTypeMasterAgentRequestCompleted</td></tr>
<tr><td>3647</td><td>master agent</td><td>7470752</td><td>✔</td><td>TlvTypeAgentMasterComm</td></tr>
<tr><td>3647</td><td>master agent</td><td>7471008</td><td>✔</td><td>TlvTypeMasterAgentRequestStatus</td></tr>
<tr><td>3648</td><td>master</td><td>7471424</td><td>✔</td><td>TlvTypeProxyMasterCommSig</td></tr>
<tr><td>3648</td><td>master</td><td>7471520</td><td>✔</td><td>TlvTypeMasterTargetConn</td></tr>
<tr><td>3648</td><td>master</td><td>7471776</td><td>✔</td><td>TlvTypeProxyMasterComm</td></tr>
<tr><td>3648</td><td>master</td><td>7472032</td><td>✔</td><td>TlvTypeMasterProxyComm</td></tr>
<tr><td>3648</td><td>master</td><td>7472288</td><td>✔</td><td>TlvTypeProxyMasterHeartBeatAnswer</td></tr>
<tr><td>3648</td><td>master</td><td>7472544</td><td>✔</td><td>TlvTypeProxyMasterDisconnect</td></tr>
<tr><td>3648</td><td>master</td><td>7472704</td><td>✔</td><td>TlvTypeProxyMasterNotification</td></tr>
<tr><td>3648</td><td>master</td><td>7473056</td><td>✔</td><td>TlvTypeProxyMasterRequest</td></tr>
<tr><td>3649</td><td>master</td><td>7473312</td><td>✔</td><td>TlvTypeMasterProxyCommNotification</td></tr>
<tr><td>3649</td><td>master</td><td>7473568</td><td>✔</td><td>TlvTypeMasterCheckTargetDisconnect</td></tr>
<tr><td>3680</td><td>target proxy</td><td>7536960</td><td>✔</td><td>TlvTypeProxyTargetCommSig</td></tr>
<tr><td>3680</td><td>target proxy</td><td>7537312</td><td>✔</td><td>TlvTypeProxyTargetComm</td></tr>
<tr><td>3680</td><td>target proxy</td><td>7537568</td><td>✔</td><td>TlvTypeProxyMasterTargetComm</td></tr>
<tr><td>3680</td><td>target proxy</td><td>7537728</td><td>✔</td><td>TlvTypeProxyTargetRequestCrypto</td></tr>
<tr><td>3680</td><td>target proxy</td><td>7538064</td><td>✔</td><td>TlvTypeProxyTargetAnswerCrypto</td></tr>
<tr><td>3744</td><td>target</td><td>7668128</td><td>✔</td><td>TlvTypeMasterTargetComm</td></tr>
<tr><td>3744</td><td>target</td><td>7668384</td><td>✔</td><td>TlvTypeTargetCloseAllLiveStreaming</td></tr>
<tr><td>3776</td><td>relay</td><td>7733664</td><td>✔</td><td>TlvTypeRelayProxyComm</td></tr>
<tr><td>3776</td><td>relay</td><td>7734176</td><td>✔</td><td>TlvTypeRelayDummyHeartbeat</td></tr>
<tr><td>4032</td><td>test type meta</td><td>8257792</td><td>✔</td><td>TlvTypeTestMetaTypeInvalid</td></tr>
<tr><td>4032</td><td>test type meta</td><td>8258608</td><td>✔</td><td>TlvTypeTestMetaTypeBool</td></tr>
<tr><td>4032</td><td>test type meta</td><td>8258880</td><td>✔</td><td>TlvTypeTestMetaTypeUInt</td></tr>
<tr><td>4032</td><td>test type meta</td><td>8259152</td><td>✔</td><td>TlvTypeTestMetaTypeInt</td></tr>
<tr><td>4032</td><td>test type meta</td><td>8259440</td><td>✔</td><td>TlvTypeTestMetaTypeString</td></tr>
<tr><td>4033</td><td>test</td><td>8259712</td><td>✔</td><td>TlvTypeTestMetaTypeUnicode</td></tr>
<tr><td>4033</td><td>test</td><td>8259984</td><td>✔</td><td>TlvTypeTestMetaTypeRaw</td></tr>
<tr><td>4033</td><td>test</td><td>8260256</td><td>✔</td><td>TlvTypeTestMetaTypeGroup</td></tr>
<tr><td>4033</td><td>test</td><td>8260416</td><td>✔</td><td>TlvTypeTestMemberIdentifier</td></tr>
<tr><td>4033</td><td>test</td><td>8260736</td><td>✔</td><td>TlvTypeTestMemberName</td></tr>
<tr><td>4096</td><td>target</td><td>8389008</td><td>✔</td><td>TlvTypeTargetData</td></tr>
<tr><td>4096</td><td>target</td><td>8389280</td><td>✔</td><td>TlvTypeTargetHeartBeat</td></tr>
<tr><td>4096</td><td>target</td><td>8389680</td><td>✔</td><td>TlvTypeTargetKeepSessionAlive</td></tr>
<tr><td>4096</td><td>target</td><td>8390000</td><td>✔</td><td>TlvTypeTargetLocalIP</td></tr>
<tr><td>4096</td><td>target</td><td>8390256</td><td>✔</td><td>TlvTypeTargetGlobalIP</td></tr>
<tr><td>4096</td><td>target</td><td>8390448</td><td>✔</td><td>TlvTypeTargetState</td></tr>
<tr><td>4097</td><td>agent master</td><td>8390784</td><td>✔</td><td>TlvTypeTargetID</td></tr>
<tr><td>4097</td><td>agent master</td><td>8391072</td><td>✔</td><td>TlvTypeGetInstalledModulesRequest</td></tr>
<tr><td>4097</td><td>agent master</td><td>8391328</td><td>✔</td><td>TlvTypeInstalledModulesReply</td></tr>
<tr><td>4097</td><td>agent master</td><td>8391488</td><td>✔</td><td>TlvTypeTrojanUID</td></tr>
<tr><td>4097</td><td>agent master</td><td>8391808</td><td>✔</td><td>TlvTypeTrojanID</td></tr>
<tr><td>4097</td><td>agent master</td><td>8392000</td><td>✔</td><td>TlvTypeTrojanMaxInfections</td></tr>
<tr><td>4097</td><td>agent master</td><td>8392240</td><td>✔</td><td>TlvTypeScreenSaverOn</td></tr>
<tr><td>4097</td><td>agent master</td><td>8392496</td><td>✔</td><td>TlvTypeScreenLocked</td></tr>
<tr><td>4098</td><td>agent master</td><td>8392752</td><td>✔</td><td>TlvTypeRecordedDataAvailable</td></tr>
<tr><td>4098</td><td>agent master</td><td>8393024</td><td>✔</td><td>TlvTypeDownloadedRecordedDataTimeStamp</td></tr>
<tr><td>4098</td><td>agent master</td><td>8393280</td><td>✔</td><td>TlvTypeInstallationMode</td></tr>
<tr><td>4098</td><td>agent master</td><td>8393552</td><td>✔</td><td>TlvTypeTargetRemoveNotification</td></tr>
<tr><td>4098</td><td>agent master</td><td>8393792</td><td>✔</td><td>TlvTypeTargetPlatformBits</td></tr>
<tr><td>4098</td><td>agent master</td><td>8394032</td><td>✔</td><td>TlvTypeRemoveItselfMaxInfectionReached</td></tr>
<tr><td>4098</td><td>agent master</td><td>8394288</td><td>✔</td><td>TlvTypeRemoveItselfAtMasterRequest</td></tr>
<tr><td>4098</td><td>agent master</td><td>8394544</td><td>✔</td><td>TlvTypeRemoveItselfAtAgentRequest</td></tr>
<tr><td>4099</td><td>agent master</td><td>8394912</td><td>✔</td><td>TlvTypeRemoveItselfAtAgentReqRequest</td></tr>
<tr><td>4099</td><td>agent master</td><td>8395072</td><td>✔</td><td>TlvTypeRecordedFilesDownloadTotal</td></tr>
<tr><td>4099</td><td>agent master</td><td>8395328</td><td>✔</td><td>TlvTypeRecordedFilesDownloadProgress</td></tr>
<tr><td>4099</td><td>agent master</td><td>8395632</td><td>✔</td><td>TlvTypeTargetLicenseInfo</td></tr>
<tr><td>4099</td><td>agent master</td><td>8395840</td><td>✔</td><td>TlvTypeRemoveTargetLicenseInfo</td></tr>
<tr><td>4099</td><td>agent master</td><td>8396176</td><td>✔</td><td>TlvTypeTargetAllConfigurations</td></tr>
<tr><td>4100</td><td>target error</td><td>8396960</td><td>✔</td><td>TlvTypeTargetError</td></tr>
<tr><td>4102</td><td>target config</td><td>8401056</td><td>✔</td><td>TlvTypeGetTargetConfigRequest</td></tr>
<tr><td>4102</td><td>target config</td><td>8401312</td><td>✔</td><td>TlvTypeTargetConfigReply</td></tr>
<tr><td>4102</td><td>target config</td><td>8401568</td><td>✔</td><td>TlvTypeSetTargetConfigRequest</td></tr>
<tr><td>4102</td><td>target config</td><td>8402304</td><td>✔</td><td>TlvTypeConfigTargetID</td></tr>
<tr><td>4102</td><td>target config</td><td>8402496</td><td>✔</td><td>TlvTypeConfigTargetHeartbeatInterval</td></tr>
<tr><td>4102</td><td>target config</td><td>8402800</td><td>✔</td><td>TlvTypeConfigTargetProxy</td></tr>
<tr><td>4103</td><td>agent master</td><td>8403008</td><td>✔</td><td>TlvTypeConfigTargetPort</td></tr>
<tr><td>4103</td><td>agent master</td><td>8403584</td><td>✔</td><td>TlvTypeConfigAutoRemovalDateTime</td></tr>
<tr><td>4103</td><td>agent master</td><td>8403776</td><td>✔</td><td>TlvTypeConfigAutoRemovalIfNoProxy</td></tr>
<tr><td>4103</td><td>agent master</td><td>8404032</td><td>✔</td><td>TlvTypeInternalAutoRemovalElapsedTime</td></tr>
<tr><td>4104</td><td>active hiding config</td><td>8405040</td><td>✔</td><td>TlvTypeConfigActiveHiding</td></tr>
<tr><td>4106</td><td>target module</td><td>8409248</td><td>✔</td><td>TlvTypeTargetLoadModuleRequest</td></tr>
<tr><td>4106</td><td>target module</td><td>8409504</td><td>✔</td><td>TlvTypeTargetLoadModuleReply</td></tr>
<tr><td>4106</td><td>target module</td><td>8409760</td><td>✔</td><td>TlvTypeTargetUnLoadModuleRequest</td></tr>
<tr><td>4106</td><td>target module</td><td>8410016</td><td>✔</td><td>TlvTypeTargetUnLoadModuleReply</td></tr>
<tr><td>4106</td><td>target module</td><td>8410272</td><td>✔</td><td>TlvTypeTargetUploadModuleRequest</td></tr>
<tr><td>4106</td><td>target module</td><td>8410528</td><td>✔</td><td>TlvTypeTargetUploadModuleReply</td></tr>
<tr><td>4106</td><td>target module</td><td>8410784</td><td>✔</td><td>TlvTypeTargetUploadModuleChunk</td></tr>
<tr><td>4106</td><td>target module</td><td>8411040</td><td>✔</td><td>TlvTypeTargetUploadModuleDoneRequest</td></tr>
<tr><td>4107</td><td>target module</td><td>8411296</td><td>✔</td><td>TlvTypeTargetUploadModuleDoneReply</td></tr>
<tr><td>4107</td><td>target module</td><td>8411552</td><td>✔</td><td>TlvTypeTargetRemoveModuleRequest</td></tr>
<tr><td>4107</td><td>target module</td><td>8411808</td><td>✔</td><td>TlvTypeTargetRemoveModuleReply</td></tr>
<tr><td>4107</td><td>target module</td><td>8412064</td><td>✔</td><td>TlvTypeTargetOfflineUploadModuleRequest</td></tr>
<tr><td>4107</td><td>target module</td><td>8412320</td><td>✔</td><td>TlvTypeTargetOfflineUploadModuleReply</td></tr>
<tr><td>4107</td><td>target module</td><td>8412576</td><td>✔</td><td>TlvTypeTargetOfflineUploadModuleChunk</td></tr>
<tr><td>4107</td><td>target module</td><td>8412832</td><td>✔</td><td>TlvTypeTargetOfflineUploadModuleDoneRequest</td></tr>
<tr><td>4107</td><td>target module</td><td>8413088</td><td>✔</td><td>TlvTypeTargetOfflineUploadModuleDoneReply</td></tr>
<tr><td>4108</td><td>target error</td><td>8413344</td><td>✔</td><td>TlvTypeTargetOfflineError</td></tr>
<tr><td>4108</td><td>target error</td><td>8413600</td><td>✔</td><td>TlvTypeTargetUploadError</td></tr>
<tr><td>4109</td><td>files reply master list agent mc</td><td>8415392</td><td>✔</td><td>TlvTypeMasterAgentListMCFilesReply</td></tr>
<tr><td>4110</td><td>target recorded</td><td>8417440</td><td>✔</td><td>TlvTypeTargetGetRecordedFilesRequest</td></tr>
<tr><td>4110</td><td>target recorded</td><td>8417696</td><td>✔</td><td>TlvTypeTargetRecordedFilesReply</td></tr>
<tr><td>4110</td><td>target recorded</td><td>8417952</td><td>✔</td><td>TlvTypeTargetRecordedFileDownloadRequest</td></tr>
<tr><td>4110</td><td>target recorded</td><td>8418208</td><td>✔</td><td>TlvTypeTargetRecordedFileDownloadReply</td></tr>
<tr><td>4110</td><td>target recorded</td><td>8418464</td><td>✔</td><td>TlvTypeTargetRecordedFileDownloadChunk</td></tr>
<tr><td>4110</td><td>target recorded</td><td>8418720</td><td>✔</td><td>TlvTypeTargetRecordedFileDownloadCompleted</td></tr>
<tr><td>4110</td><td>target recorded</td><td>8418976</td><td>✔</td><td>TlvTypeTargetRecordedFileDeleteRequest</td></tr>
<tr><td>4110</td><td>target recorded</td><td>8419232</td><td>✔</td><td>TlvTypeTargetRecordedFileDeleteReply</td></tr>
<tr><td>4111</td><td>target recorded ex</td><td>8419488</td><td>✔</td><td>TlvTypeTargetGetRecordedFilesRequestEx</td></tr>
<tr><td>4111</td><td>target recorded ex</td><td>8419744</td><td>✔</td><td>TlvTypeTargetRecordedFilesReplyEx</td></tr>
<tr><td>4111</td><td>target recorded ex</td><td>8420000</td><td>✔</td><td>TlvTypeTargetRecordedFileDeleteRequestEx</td></tr>
<tr><td>4111</td><td>target recorded ex</td><td>8420256</td><td>✔</td><td>TlvTypeTargetRecordedFilesDownloadRequestEx</td></tr>
<tr><td>4128</td><td>data</td><td>8454544</td><td>✔</td><td>TlvTypeProxyData</td></tr>
<tr><td>4128</td><td>data</td><td>8454800</td><td>✔</td><td>TlvTypeRelayData</td></tr>
<tr><td>4130</td><td>proxy</td><td>8458400</td><td>✔</td><td>TlvTypeProxyTargetDisconnect</td></tr>
<tr><td>4130</td><td>proxy</td><td>8458656</td><td>✔</td><td>TlvTypeProxyMobileTargetDisconnect</td></tr>
<tr><td>4130</td><td>proxy</td><td>8458912</td><td>✔</td><td>TlvTypeProxyDummyHeartbeat</td></tr>
<tr><td>4130</td><td>proxy</td><td>8459168</td><td>✔</td><td>TlvTypeProxyMobileDummyHeartbeat</td></tr>
<tr><td>4160</td><td>master</td><td>8520080</td><td>✔</td><td>TlvTypeMasterData</td></tr>
<tr><td>4160</td><td>master</td><td>8520768</td><td>✔</td><td>TlvTypeMasterMode</td></tr>
<tr><td>4160</td><td>master</td><td>8521024</td><td>✔</td><td>TlvTypeMasterToken</td></tr>
<tr><td>4160</td><td>master</td><td>8521344</td><td>✔</td><td>TlvTypeMasterQueryResult</td></tr>
<tr><td>4161</td><td>string master alarm</td><td>8522368</td><td>✔</td><td>TlvTypeMasterAlarmString</td></tr>
<tr><td>4192</td><td>agent</td><td>8585616</td><td>✔</td><td>TlvTypeAgentData</td></tr>
<tr><td>4192</td><td>agent</td><td>8585808</td><td>✔</td><td>TlvTypeAgentQueryID</td></tr>
<tr><td>4192</td><td>agent</td><td>8586048</td><td>✔</td><td>TlvTypeAgentQueryModSubmodID</td></tr>
<tr><td>4192</td><td>agent</td><td>8586304</td><td>✔</td><td>TlvTypeAgentQueryFromDate</td></tr>
<tr><td>4192</td><td>agent</td><td>8586560</td><td>✔</td><td>TlvTypeAgentQueryToDate</td></tr>
<tr><td>4192</td><td>agent</td><td>8586816</td><td>✔</td><td>TlvTypeAgentQuerySortOrder</td></tr>
<tr><td>4192</td><td>agent</td><td>8587136</td><td>✔</td><td>TlvTypeAgentQueryValueFilter</td></tr>
<tr><td>4193</td><td>uid agent</td><td>8587328</td><td>✔</td><td>TlvTypeAgentUID</td></tr>
<tr><td>4224</td><td>mobile</td><td>8651152</td><td>✔</td><td>TlvTypeMobileTargetData</td></tr>
<tr><td>4224</td><td>mobile</td><td>8651376</td><td>✔</td><td>TlvTypeMobileTargetHeartBeatV10</td></tr>
<tr><td>4224</td><td>mobile</td><td>8651632</td><td>✔</td><td>TlvTypeMobileTargetExtendedHeartBeatV10</td></tr>
<tr><td>4224</td><td>mobile</td><td>8651888</td><td>✔</td><td>TlvTypeMobileHeartBeatReplyV10</td></tr>
<tr><td>4225</td><td>installed reply modules mobile</td><td>8653472</td><td>✔</td><td>TlvTypeMobileInstalledModulesReply</td></tr>
<tr><td>4225</td><td>installed reply modules mobile</td><td>8652912</td><td>×</td><td>unknown</td></tr>
<tr><td>4226</td><td>module upload mobile target</td><td>8655008</td><td>✔</td><td>TlvTypeMobileTargetOfflineUploadModuleRequest</td></tr>
<tr><td>4226</td><td>module upload mobile target</td><td>8656032</td><td>✔</td><td>TlvTypeMobileTargetUploadModuleRequest</td></tr>
<tr><td>4226</td><td>module upload mobile target</td><td>8656288</td><td>✔</td><td>TlvTypeMobileTargetUploadModuleReply</td></tr>
<tr><td>4226</td><td>module upload mobile target</td><td>8656544</td><td>✔</td><td>TlvTypeMobileTargetUploadModuleChunk</td></tr>
<tr><td>4226</td><td>module upload mobile target</td><td>8656800</td><td>✔</td><td>TlvTypeMobileTargetUploadModuleDoneRequest</td></tr>
<tr><td>4227</td><td>target mobile</td><td>8657056</td><td>✔</td><td>TlvTypeMobileTargetUploadModuleDoneReply</td></tr>
<tr><td>4227</td><td>target mobile</td><td>8657312</td><td>✔</td><td>TlvTypeMobileTargetRemoveModuleRequest</td></tr>
<tr><td>4227</td><td>target mobile</td><td>8657568</td><td>✔</td><td>TlvTypeMobileTargetRemoveModuleReply</td></tr>
<tr><td>4227</td><td>target mobile</td><td>8657824</td><td>✔</td><td>TlvTypeMobileTargetOfflineUploadModuleReply</td></tr>
<tr><td>4227</td><td>target mobile</td><td>8658080</td><td>✔</td><td>TlvTypeMobileTargetOfflineUploadModuleChunk</td></tr>
<tr><td>4227</td><td>target mobile</td><td>8658336</td><td>✔</td><td>TlvTypeMobileTargetOfflineUploadModuleDoneRequest</td></tr>
<tr><td>4227</td><td>target mobile</td><td>8658592</td><td>✔</td><td>TlvTypeMobileTargetOfflineUploadModuleDoneReply</td></tr>
<tr><td>4227</td><td>target mobile</td><td>8658848</td><td>✔</td><td>TlvTypeMobileTargetOfflineError</td></tr>
<tr><td>4228</td><td>mobile target</td><td>8659104</td><td>✔</td><td>TlvTypeMobileTargetError</td></tr>
<tr><td>4228</td><td>mobile target</td><td>8659360</td><td>✔</td><td>TlvTypeMobileTargetGetRecordedFilesRequest</td></tr>
<tr><td>4228</td><td>mobile target</td><td>8659616</td><td>✔</td><td>TlvTypeMobileTargetRecordedFilesReply</td></tr>
<tr><td>4228</td><td>mobile target</td><td>8659872</td><td>✔</td><td>TlvTypeMobileTargetRecordedFileDownloadRequest</td></tr>
<tr><td>4228</td><td>mobile target</td><td>8660128</td><td>✔</td><td>TlvTypeMobileTargetRecordedFileDownloadReply</td></tr>
<tr><td>4228</td><td>mobile target</td><td>8660384</td><td>✔</td><td>TlvTypeMobileTargetRecordedFileDownloadChunk</td></tr>
<tr><td>4228</td><td>mobile target</td><td>8660640</td><td>✔</td><td>TlvTypeMobileTargetRecordedFileDownloadCompleted</td></tr>
<tr><td>4228</td><td>mobile target</td><td>8660896</td><td>✔</td><td>TlvTypeMobileTargetRecordedFileDeleteRequest</td></tr>
<tr><td>4229</td><td>target reply delete mobile recorded file</td><td>8661152</td><td>✔</td><td>TlvTypeMobileTargetRecordedFileDeleteReply</td></tr>
<tr><td>4230</td><td>mobile config target</td><td>8663968</td><td>✔</td><td>TlvTypeMobileTargetOfflineConfig</td></tr>
<tr><td>4230</td><td>mobile config target</td><td>8664224</td><td>✔</td><td>TlvTypeMobileTargetEmergencyConfigAsTLV</td></tr>
<tr><td>4230</td><td>mobile config target</td><td>8664432</td><td>✔</td><td>TlvTypeMobileTargetEmergencyConfig</td></tr>
<tr><td>4234</td><td>load module mobile target</td><td>8671392</td><td>✔</td><td>TlvTypeMobileTargetLoadModuleRequest</td></tr>
<tr><td>4234</td><td>load module mobile target</td><td>8671648</td><td>✔</td><td>TlvTypeMobileTargetLoadModuleReply</td></tr>
<tr><td>4234</td><td>load module mobile target</td><td>8671904</td><td>✔</td><td>TlvTypeMobileTargetUnLoadModuleRequest</td></tr>
<tr><td>4234</td><td>load module mobile target</td><td>8672160</td><td>✔</td><td>TlvTypeMobileTargetUnLoadModuleReply</td></tr>
<tr><td>4236</td><td>target error</td><td>8675472</td><td>✔</td><td>TlvTypeMobileTargetHeartbeatEvents</td></tr>
<tr><td>4236</td><td>agent master files mc reply list</td><td>8675648</td><td>✔</td><td>TlvTypeMobileTargetHeartbeatInterval</td></tr>
<tr><td>4236</td><td>recorded target</td><td>8675984</td><td>✔</td><td>TlvTypeMobileTargetHeartbeatRestrictions</td></tr>
<tr><td>4236</td><td>recorded target</td><td>8676208</td><td>✔</td><td>TlvTypeConfigSMSPhoneNumber</td></tr>
<tr><td>4236</td><td>recorded target</td><td>8676496</td><td>✔</td><td>TlvTypeMobileTargetPositioning</td></tr>
<tr><td>4236</td><td>recorded target</td><td>8676672</td><td>✔</td><td>TlvTypeMobileTrojanUID</td></tr>
<tr><td>4236</td><td>recorded target</td><td>8676976</td><td>✔</td><td>TlvTypeMobileTrojanID</td></tr>
<tr><td>4236</td><td>recorded target</td><td>8677296</td><td>✔</td><td>TlvTypeMobileTargetLocationChangedRange</td></tr>
<tr><td>4237</td><td>config</td><td>8677440</td><td>✔</td><td>TlvTypeConfigMobileAutoRemovalDateTime</td></tr>
<tr><td>4237</td><td>config</td><td>8677808</td><td>✔</td><td>TlvTypeConfigOverwriteProxyAndPhones</td></tr>
<tr><td>4237</td><td>config</td><td>8678000</td><td>✔</td><td>TlvTypeConfigCallPhoneNumber</td></tr>
<tr><td>4238</td><td>ex recorded target</td><td>8679488</td><td>✔</td><td>TlvTypeLocationAreaCode</td></tr>
<tr><td>4238</td><td>ex recorded target</td><td>8679744</td><td>✔</td><td>TlvTypeCellID</td></tr>
<tr><td>4238</td><td>ex recorded target</td><td>8680048</td><td>✔</td><td>TlvTypeMobileCountryCode</td></tr>
<tr><td>4238</td><td>data</td><td>8680304</td><td>✔</td><td>TlvTypeMobileNetworkCode</td></tr>
<tr><td>4238</td><td>data</td><td>8680560</td><td>✔</td><td>TlvTypeIMSI</td></tr>
<tr><td>4238</td><td>proxy</td><td>8680816</td><td>✔</td><td>TlvTypeIMEI</td></tr>
<tr><td>4238</td><td>proxy</td><td>8681072</td><td>✔</td><td>TlvTypeGPSLatitude</td></tr>
<tr><td>4238</td><td>proxy</td><td>8681328</td><td>✔</td><td>TlvTypeGPSLongitude</td></tr>
<tr><td>4239</td><td>proxy</td><td>8681520</td><td>✔</td><td>TlvTypeFirstHeartbeat</td></tr>
<tr><td>4239</td><td>master</td><td>8681872</td><td>✔</td><td>TlvTypeInstalledModules</td></tr>
<tr><td>4240</td><td>gps valid values</td><td>8683568</td><td>✔</td><td>TlvTypeValidGPSValues</td></tr>
<tr><td>4288</td><td>mobile proxy comm target</td><td>8782176</td><td>✔</td><td>TlvTypeProxyMobileTargetCommSig</td></tr>
<tr><td>4288</td><td>mobile proxy comm target</td><td>8782496</td><td>✔</td><td>TlvTypeProxyMobileTargetComm</td></tr>
<tr><td>4288</td><td>mobile proxy comm target</td><td>8782752</td><td>✔</td><td>TlvTypeProxyMasterMobileTargetComm</td></tr>
<tr><td>4384</td><td>master mobile</td><td>8978752</td><td>✔</td><td>TlvTypeMobileProxyMasterCommSig</td></tr>
<tr><td>4384</td><td>master mobile</td><td>8978848</td><td>✔</td><td>TlvTypeMasterMobileTargetConn</td></tr>
<tr><td>4384</td><td>master mobile</td><td>8979104</td><td>✔</td><td>TlvTypeMobileProxyMasterComm</td></tr>
<tr><td>4384</td><td>master mobile</td><td>8979360</td><td>✔</td><td>TlvTypeMobileMasterProxyComm</td></tr>
<tr><td>4384</td><td>master mobile</td><td>8979616</td><td>✔</td><td>TlvTypeProxyMasterMobileHeartBeatAnswer</td></tr>
<tr><td>4384</td><td>master mobile</td><td>8979872</td><td>✔</td><td>TlvTypeMobileMasterProxyCommNotification</td></tr>
<tr><td>8128</td><td>agent</td><td>16646544</td><td>✔</td><td>TlvTypePlaintext</td></tr>
<tr><td>8128</td><td>agent uid</td><td>16646800</td><td>✔</td><td>TlvTypeCompression</td></tr>
<tr><td>8128</td><td>mobile</td><td>16647056</td><td>✔</td><td>TlvTypeEncryption</td></tr>
<tr><td>8128</td><td>mobile</td><td>16647232</td><td>✔</td><td>TlvTypeTargetUID</td></tr>
<tr><td>8128</td><td>mobile</td><td>16647536</td><td>✔</td><td>TlvTypeIPAddress</td></tr>
<tr><td>8128</td><td>mobile</td><td>16647808</td><td>✔</td><td>TlvTypeUserName</td></tr>
<tr><td>8128</td><td>installed reply modules mobile</td><td>16648064</td><td>✔</td><td>TlvTypeComputerName</td></tr>
<tr><td>8129</td><td>installed reply modules mobile</td><td>16648304</td><td>✔</td><td>TlvTypeLoginName</td></tr>
<tr><td>8129</td><td>module upload mobile target</td><td>16648560</td><td>✔</td><td>TlvTypePassphrase</td></tr>
<tr><td>8129</td><td>module upload mobile target</td><td>16648832</td><td>✔</td><td>TlvTypeRecordID</td></tr>
<tr><td>8129</td><td>module upload mobile target</td><td>16649088</td><td>✔</td><td>TlvTypeOwner</td></tr>
<tr><td>8129</td><td>module upload mobile target</td><td>16649344</td><td>✔</td><td>TlvTypeMetaData</td></tr>
<tr><td>8129</td><td>module upload mobile target</td><td>16649536</td><td>✔</td><td>TlvTypeModuleID</td></tr>
<tr><td>8129</td><td>mobile target</td><td>16649856</td><td>✔</td><td>TlvTypeOSName</td></tr>
<tr><td>8129</td><td>mobile target</td><td>16650048</td><td>✔</td><td>TlvTypeModuleSubID</td></tr>
<tr><td>8130</td><td>mobile target</td><td>16650320</td><td>✔</td><td>TlvTypeErrorCode</td></tr>
<tr><td>8130</td><td>mobile target</td><td>16650560</td><td>✔</td><td>TlvTypeOffset</td></tr>
<tr><td>8130</td><td>mobile target</td><td>16650816</td><td>✔</td><td>TlvTypeLength</td></tr>
<tr><td>8130</td><td>mobile target</td><td>16651088</td><td>✔</td><td>TlvTypeRequestID</td></tr>
<tr><td>8130</td><td>mobile target</td><td>16651328</td><td>✔</td><td>TlvTypeRequestType</td></tr>
<tr><td>8130</td><td>mobile target</td><td>16651584</td><td>✔</td><td>TlvTypeVersion</td></tr>
<tr><td>8130</td><td>mobile target</td><td>16651840</td><td>✔</td><td>TlvTypeMachineID</td></tr>
<tr><td>8130</td><td>mobile target</td><td>16652096</td><td>✔</td><td>TlvTypeMajorNumber</td></tr>
<tr><td>8131</td><td>mobile target</td><td>16652352</td><td>✔</td><td>TlvTypeMinorNumber</td></tr>
<tr><td>8131</td><td>mobile target</td><td>16652656</td><td>✔</td><td>TlvTypeGlobalIPAddress</td></tr>
<tr><td>8131</td><td>mobile target</td><td>16652912</td><td>✔</td><td>TlvTypeASCII_Filename</td></tr>
<tr><td>8131</td><td>mobile target</td><td>16653120</td><td>✔</td><td>TlvTypeFilesize</td></tr>
<tr><td>8131</td><td>mobile target</td><td>16653392</td><td>✔</td><td>TlvTypeFilecount</td></tr>
<tr><td>8131</td><td>mobile target</td><td>16653712</td><td>✔</td><td>TlvTypeFiledata</td></tr>
<tr><td>8131</td><td>target reply recorded delete file mobile</td><td>16653968</td><td>✔</td><td>TlvTypeMD5Sum</td></tr>
<tr><td>8131</td><td>mobile target config</td><td>16654144</td><td>✔</td><td>TlvTypeProxyPort</td></tr>
<tr><td>8132</td><td>mobile target config</td><td>16654400</td><td>✔</td><td>TlvTypeStatus</td></tr>
<tr><td>8132</td><td>mobile target config</td><td>16654656</td><td>✔</td><td>TlvTypeUserID</td></tr>
<tr><td>8132</td><td>module load mobile target</td><td>16654912</td><td>✔</td><td>TlvTypeGroupID</td></tr>
<tr><td>8132</td><td>module load mobile target</td><td>16655168</td><td>✔</td><td>TlvTypePermissions</td></tr>
<tr><td>8132</td><td>module load mobile target</td><td>16655424</td><td>✔</td><td>TlvTypeRequestCode</td></tr>
<tr><td>8132</td><td>module load mobile target</td><td>16655680</td><td>✔</td><td>TlvTypeDataSize</td></tr>
<tr><td>8132</td><td></td><td>16655936</td><td>✔</td><td>TlvTypeKeyType</td></tr>
<tr><td>8132</td><td></td><td>16656240</td><td>✔</td><td>TlvTypeEmail</td></tr>
<tr><td>8133</td><td></td><td>16656432</td><td>✔</td><td>TlvTypeEnabled</td></tr>
<tr><td>8133</td><td></td><td>16656688</td><td>✔</td><td>TlvTypeLicensed</td></tr>
<tr><td>8133</td><td></td><td>16656960</td><td>✔</td><td>TlvTypeAudioFrequency</td></tr>
<tr><td>8133</td><td></td><td>16657216</td><td>✔</td><td>TlvTypeAudioBitsPerSample</td></tr>
<tr><td>8133</td><td></td><td>16657472</td><td>✔</td><td>TlvTypeAudioChannels</td></tr>
<tr><td>8133</td><td></td><td>16657728</td><td>✔</td><td>TlvTypeStartTime</td></tr>
<tr><td>8133</td><td>config</td><td>16657984</td><td>✔</td><td>TlvTypeStopTime</td></tr>
<tr><td>8133</td><td>config</td><td>16658240</td><td>✔</td><td>TlvTypeBitMask</td></tr>
<tr><td>8134</td><td>config</td><td>16658560</td><td>✔</td><td>TlvTypeTimeZone</td></tr>
<tr><td>8134</td><td></td><td>16658816</td><td>✔</td><td>TlvTypeDateTime</td></tr>
<tr><td>8134</td><td></td><td>16659072</td><td>✔</td><td>TlvTypeStartSessionDateTime</td></tr>
<tr><td>8134</td><td></td><td>16659328</td><td>✔</td><td>TlvTypeStopSessionDateTime</td></tr>
<tr><td>8134</td><td></td><td>16659520</td><td>✔</td><td>TlvTypeDateTimeRef</td></tr>
<tr><td>8134</td><td></td><td>16659776</td><td>✔</td><td>TlvTypeScheduleRepeat</td></tr>
<tr><td>8134</td><td></td><td>16660032</td><td>✔</td><td>TlvTypeUnixMasterDateTime</td></tr>
<tr><td>8134</td><td></td><td>16660288</td><td>✔</td><td>TlvTypeUnixUTCDateTime</td></tr>
<tr><td>8135</td><td></td><td>16660544</td><td>✔</td><td>TlvTypeDurationInSeconds</td></tr>
<tr><td>8135</td><td></td><td>16660864</td><td>✔</td><td>TlvTypeMasterRefTime</td></tr>
<tr><td>8135</td><td></td><td>16661120</td><td>✔</td><td>TlvTypeMasterRefTimeStart</td></tr>
<tr><td>8135</td><td>values gps valid</td><td>16661376</td><td>✔</td><td>TlvTypeMasterRefTimeEnd</td></tr>
<tr><td>8135</td><td></td><td>16661568</td><td>✔</td><td>TlvTypeCounter</td></tr>
<tr><td>8135</td><td></td><td>16661888</td><td>✔</td><td>TlvTypeWhiteListEntry</td></tr>
<tr><td>8135</td><td></td><td>16662144</td><td>✔</td><td>TlvTypeBlackListEntry</td></tr>
<tr><td>8135</td><td></td><td>16662336</td><td>✔</td><td>TlvTypeBlackWhiteListingMode</td></tr>
<tr><td>8136</td><td>config</td><td>16662576</td><td>✔</td><td>TlvTypeConfigEnabled</td></tr>
<tr><td>8136</td><td>config</td><td>16662848</td><td>✔</td><td>TlvTypeConfigMaxRecordingSize</td></tr>
<tr><td>8136</td><td>config</td><td>16663104</td><td>✔</td><td>TlvTypeConfigAudioQuality</td></tr>
<tr><td>8136</td><td>config</td><td>16663344</td><td>✔</td><td>TlvTypeConfigVideoBlackAndWhite</td></tr>
<tr><td>8136</td><td>config</td><td>16663616</td><td>✔</td><td>TlvTypeConfigVideoResolution</td></tr>
<tr><td>8136</td><td>config</td><td>16663872</td><td>✔</td><td>TlvTypeConfigCaptureFrequency</td></tr>
<tr><td>8136</td><td>config</td><td>16664128</td><td>✔</td><td>TlvTypeConfigVideoQuality</td></tr>
<tr><td>8136</td><td>config</td><td>16664384</td><td>✔</td><td>TlvTypeConfigFilesStandardFilter</td></tr>
<tr><td>8137</td><td>config</td><td>16664704</td><td>✔</td><td>TlvTypeConfigFilesCustomFilter</td></tr>
<tr><td>8137</td><td>config</td><td>16664896</td><td>✔</td><td>TlvTypeConfigStandardLocation</td></tr>
<tr><td>8137</td><td>config</td><td>16665216</td><td>✔</td><td>TlvTypeConfigCustomLocation</td></tr>
<tr><td>8137</td><td>config</td><td>16665408</td><td>✔</td><td>TlvTypeConfigFileChunkSize</td></tr>
<tr><td>8137</td><td>config</td><td>16665664</td><td>✔</td><td>TlvTypeConfigFileTransferSpeed</td></tr>
<tr><td>8137</td><td>config</td><td>16665904</td><td>✔</td><td>TlvTypeConfigUploadFileOverwrite</td></tr>
<tr><td>8137</td><td>config</td><td>16666160</td><td>✔</td><td>TlvTypeConfigDeleteOverReboot</td></tr>
<tr><td>8137</td><td>config</td><td>16666496</td><td>✔</td><td>TlvTypeConfigCustomLocationException</td></tr>
<tr><td>8138</td><td>master mobile</td><td>16666752</td><td>✔</td><td>TlvTypeExtraData</td></tr>
<tr><td>8138</td><td>master mobile</td><td>16667008</td><td>✔</td><td>TlvTypeSignature</td></tr>
<tr><td>8138</td><td></td><td>16667264</td><td>✔</td><td>TlvTypeComments</td></tr>
<tr><td>8138</td><td></td><td>16667520</td><td>✔</td><td>TlvTypeDescription</td></tr>
<tr><td>8138</td><td></td><td>16667776</td><td>✔</td><td>TlvTypeFilenameExtension</td></tr>
<tr><td>8138</td><td></td><td>16668032</td><td>✔</td><td>TlvTypeSessionType</td></tr>
<tr><td>8138</td><td></td><td>16668224</td><td>✔</td><td>TlvTypePeriod</td></tr>
<tr><td>8138</td><td></td><td>16668512</td><td>✔</td><td>TlvTypeMobileTargetUID</td></tr>
<tr><td>8139</td><td></td><td>16668784</td><td>✔</td><td>TlvTypeMobileTargetID</td></tr>
<tr><td>8139</td><td></td><td>16669072</td><td>✔</td><td>TlvTypeMobilePlaintext</td></tr>
<tr><td>8139</td><td></td><td>16669328</td><td>✔</td><td>TlvTypeMobileCompression</td></tr>
<tr><td>8139</td><td></td><td>16669584</td><td>✔</td><td>TlvTypeMobileEncryption</td></tr>
<tr><td>8139</td><td></td><td>16669824</td><td>✔</td><td>TlvTypeEncodingType</td></tr>
<tr><td>8139</td><td></td><td>16670576</td><td>✔</td><td>TlvTypePhoneNumber</td></tr>
<tr><td>8140</td><td>custom config location mode</td><td>16670784</td><td>✔</td><td>TlvTypeConfigCustomLocationMode</td></tr>
<tr><td>8140</td><td>custom config location mode</td><td>16672080</td><td>×</td><td>unknown</td></tr>
<tr><td>8140</td><td>custom config location mode</td><td>16671792</td><td>×</td><td>unknown</td></tr>
<tr><td>8142</td><td>network interface</td><td>16674928</td><td>✔</td><td>TlvTypeNetworkInterface</td></tr>
<tr><td>8142</td><td>network interface</td><td>16675136</td><td>✔</td><td>TlvTypeNetworkInterfaceMode</td></tr>
<tr><td>8142</td><td>network interface</td><td>16675440</td><td>✔</td><td>TlvTypeNetworkInterfaceAddress</td></tr>
<tr><td>8142</td><td>network interface</td><td>16675696</td><td>✔</td><td>TlvTypeNetworkInterfaceNetmask</td></tr>
<tr><td>8142</td><td>network interface</td><td>16675952</td><td>✔</td><td>TlvTypeNetworkInterfaceGateway</td></tr>
<tr><td>8142</td><td>network interface</td><td>16676208</td><td>✔</td><td>TlvTypeNetworkInterfaceDNS_1</td></tr>
<tr><td>8142</td><td>network interface</td><td>16676464</td><td>✔</td><td>TlvTypeNetworkInterfaceDNS_2</td></tr>
<tr><td>8143</td><td></td><td>16677440</td><td>✔</td><td>TlvTypeLoginTime</td></tr>
<tr><td>8143</td><td></td><td>16677696</td><td>✔</td><td>TlvTypeLogoffTime</td></tr>
<tr><td>8143</td><td></td><td>16678720</td><td>✔</td><td>TlvTypeGeneric_Type</td></tr>
<tr><td>8144</td><td></td><td>16678976</td><td>✔</td><td>TlvTypeChecksum</td></tr>
<tr><td>8144</td><td></td><td>16679280</td><td>✔</td><td>TlvTypeCity</td></tr>
<tr><td>8144</td><td></td><td>16679536</td><td>✔</td><td>TlvTypeCountry</td></tr>
<tr><td>8144</td><td></td><td>16679792</td><td>✔</td><td>TlvTypeCountryCode</td></tr>
<tr><td>8146</td><td></td><td>16683072</td><td>✔</td><td>TlvTypeTargetType</td></tr>
<tr><td>8146</td><td></td><td>16683392</td><td>✔</td><td>TlvTypeDurationString</td></tr>
<tr><td>8146</td><td></td><td>16683904</td><td>×</td><td>unknown</td></tr>
<tr><td>8146</td><td></td><td>16684848</td><td>×</td><td>unknown</td></tr>
<tr><td>8160</td><td></td><td>16712000</td><td>✔</td><td>TlvTypeTargetConnectionBroken</td></tr>
<tr><td>8160</td><td></td><td>16712256</td><td>✔</td><td>TlvTypeAgentConnectionBroken</td></tr>
<tr><td>8160</td><td></td><td>16712512</td><td>✔</td><td>TlvTypeTargetOffline</td></tr>
<tr><td>8176</td><td></td><td>16744768</td><td>✔</td><td>TlvTypeProxyConnectionBroken</td></tr>
<tr><td>4242</td><td></td><td>8688960</td><td>×</td><td>unknown</td></tr>
<tr><td>4242</td><td></td><td>8689296</td><td>×</td><td>unknown</td></tr>
<tr><td>4242</td><td></td><td>8689568</td><td>×</td><td>unknown</td></tr>
<tr><td>2752</td><td></td><td>5636992</td><td>×</td><td>unknown</td></tr>
<tr><td>2752</td><td></td><td>5637504</td><td>×</td><td>unknown</td></tr>
<tr><td>2752</td><td></td><td>5637760</td><td>×</td><td>unknown</td></tr>
<tr><td>2752</td><td></td><td>5636464</td><td>×</td><td>unknown</td></tr>
<tr><td>2752</td><td></td><td>5636736</td><td>×</td><td>unknown</td></tr>
<tr><td>2752</td><td></td><td>5637248</td><td>×</td><td>unknown</td></tr>
<tr><td>2753</td><td></td><td>5638256</td><td>×</td><td>unknown</td></tr>
<tr><td>2753</td><td></td><td>5638768</td><td>×</td><td>unknown</td></tr>
<tr><td>2754</td><td></td><td>5641600</td><td>×</td><td>unknown</td></tr>
<tr><td>2754</td><td></td><td>5640608</td><td>×</td><td>unknown</td></tr>
<tr><td>2754</td><td></td><td>5641120</td><td>×</td><td>unknown</td></tr>
<tr><td>2754</td><td></td><td>5640864</td><td>×</td><td>unknown</td></tr>
<tr><td>2754</td><td></td><td>5640352</td><td>×</td><td>unknown</td></tr>
<tr><td>2218</td><td></td><td>4542832</td><td>×</td><td>unknown</td></tr>
<tr><td>2218</td><td></td><td>4542624</td><td>×</td><td>unknown</td></tr>
<tr><td>8147</td><td></td><td>16685104</td><td>×</td><td>unknown</td></tr>
<tr><td>8147</td><td></td><td>16685392</td><td>×</td><td>unknown</td></tr>
<tr><td>2658</td><td></td><td>5444000</td><td>×</td><td>unknown</td></tr>
<tr><td>2658</td><td></td><td>5444512</td><td>×</td><td>unknown</td></tr>
<tr><td>2656</td><td></td><td>5440320</td><td>×</td><td>unknown</td></tr>
<tr><td>2656</td><td></td><td>5439904</td><td>×</td><td>unknown</td></tr>
<tr><td>2660</td><td></td><td>5447840</td><td>×</td><td>unknown</td></tr>
<tr><td>2722</td><td></td><td>5575072</td><td>×</td><td>unknown</td></tr>
<tr><td>2722</td><td></td><td>5575328</td><td>×</td><td>unknown</td></tr>
<tr><td>2722</td><td>config</td><td>5575840</td><td>×</td><td>unknown</td></tr>
<tr><td>2560</td><td>config</td><td>5243552</td><td>×</td><td>unknown</td></tr>
<tr><td>2560</td><td>config</td><td>5243296</td><td>×</td><td>unknown</td></tr>
<tr><td>4244</td><td>config</td><td>8693104</td><td>×</td><td>unknown</td></tr>
<tr><td>4244</td><td>config</td><td>8692080</td><td>×</td><td>unknown</td></tr>
<tr><td>4244</td><td>config</td><td>8692336</td><td>×</td><td>unknown</td></tr>
<tr><td>4244</td><td>config</td><td>8692592</td><td>×</td><td>unknown</td></tr>
<tr><td>4244</td><td>config</td><td>8692848</td><td>×</td><td>unknown</td></tr>
<tr><td>4244</td><td>config</td><td>8693360</td><td>×</td><td>unknown</td></tr>
<tr><td>4244</td><td>config</td><td>8691872</td><td>×</td><td>unknown</td></tr>
<tr><td>2690</td><td>config</td><td>5509536</td><td>×</td><td>unknown</td></tr>
<tr><td>2690</td><td>config</td><td>5510048</td><td>×</td><td>unknown</td></tr>
<tr><td>2692</td><td>config</td><td>5513376</td><td>×</td><td>unknown</td></tr>
<tr><td>2688</td><td>config</td><td>5505856</td><td>×</td><td>unknown</td></tr>
<tr><td>2688</td><td>config</td><td>5505440</td><td>×</td><td>unknown</td></tr>
<tr><td>2592</td><td>config</td><td>5309088</td><td>×</td><td>unknown</td></tr>
<tr><td>2602</td><td></td><td>5329824</td><td>×</td><td>unknown</td></tr>
<tr><td>2602</td><td></td><td>5330592</td><td>×</td><td>unknown</td></tr>
<tr><td>2602</td><td></td><td>5329568</td><td>×</td><td>unknown</td></tr>
<tr><td>2602</td><td></td><td>5330080</td><td>×</td><td>unknown</td></tr>
<tr><td>2596</td><td></td><td>5317536</td><td>×</td><td>unknown</td></tr>
<tr><td>2596</td><td></td><td>5317792</td><td>×</td><td>unknown</td></tr>
<tr><td>2596</td><td></td><td>5318048</td><td>×</td><td>unknown</td></tr>
<tr><td>2596</td><td></td><td>5317280</td><td>×</td><td>unknown</td></tr>
<tr><td>2594</td><td></td><td>5313440</td><td>×</td><td>unknown</td></tr>
<tr><td>2594</td><td></td><td>5312928</td><td>×</td><td>unknown</td></tr>
<tr><td>2594</td><td></td><td>5313184</td><td>×</td><td>unknown</td></tr>
<tr><td>2600</td><td></td><td>5325216</td><td>×</td><td>unknown</td></tr>
<tr><td>2598</td><td></td><td>5321376</td><td>×</td><td>unknown</td></tr>
<tr><td>2598</td><td></td><td>5322144</td><td>×</td><td>unknown</td></tr>
<tr><td>2784</td><td>mode location custom config</td><td>5703584</td><td>×</td><td>unknown</td></tr>
<tr><td>2784</td><td>mode location custom config</td><td>5703328</td><td>×</td><td>unknown</td></tr>
<tr><td>2784</td><td>mode location custom config</td><td>5702816</td><td>×</td><td>unknown</td></tr>
<tr><td>2784</td><td>interface network</td><td>5702032</td><td>×</td><td>unknown</td></tr>
<tr><td>2784</td><td>interface network</td><td>5702304</td><td>×</td><td>unknown</td></tr>
<tr><td>2785</td><td>interface network</td><td>5703808</td><td>×</td><td>unknown</td></tr>
<tr><td>2785</td><td>interface network</td><td>5704064</td><td>×</td><td>unknown</td></tr>
<tr><td>1757</td><td>interface network</td><td>3600000</td><td>×</td><td>unknown</td></tr>
<tr><td>2696</td><td>interface network</td><td>5521552</td><td>×</td><td>unknown</td></tr>
<tr><td>2696</td><td>interface network</td><td>5521568</td><td>×</td><td>unknown</td></tr>
<tr><td>2720</td><td></td><td>5570960</td><td>×</td><td>unknown</td></tr>
<tr><td>2720</td><td></td><td>5571232</td><td>×</td><td>unknown</td></tr>
<tr><td>2756</td><td></td><td>5644432</td><td>×</td><td>unknown</td></tr>
<tr><td>2756</td><td></td><td>5644704</td><td>×</td><td>unknown</td></tr>
<tr><td>2848</td><td></td><td>5833104</td><td>×</td><td>unknown</td></tr>
<tr><td>2848</td><td></td><td>5833376</td><td>×</td><td>unknown</td></tr>
<tr><td>3104</td><td></td><td>6357392</td><td>×</td><td>unknown</td></tr>
<tr><td>3104</td><td></td><td>6357664</td><td>×</td><td>unknown</td></tr>
<tr><td>2664</td><td></td><td>5456016</td><td>×</td><td>unknown</td></tr>
<tr><td>2664</td><td></td><td>5456288</td><td>×</td><td>unknown</td></tr>
<tr><td>4243</td><td></td><td>8690064</td><td>×</td><td>unknown</td></tr>
<tr><td>4243</td><td></td><td>8690336</td><td>×</td><td>unknown</td></tr>
<tr><td>4243</td><td></td><td>8689712</td><td>×</td><td>unknown</td></tr>
<tr><td>2304</td><td></td><td>4719008</td><td>×</td><td>unknown</td></tr>
<tr><td>2304</td><td></td><td>4719232</td><td>×</td><td>unknown</td></tr>
<tr><td>3106</td><td></td><td>6361200</td><td>×</td><td>unknown</td></tr>
<tr><td>16425</td><td></td><td>33639248</td><td>×</td><td>unknown</td></tr>
<tr><td>48781</td><td></td><td>99903492</td><td>×</td><td>unknown</td></tr>
<tr><td>41609</td><td></td><td>85215461</td><td>×</td><td>unknown</td></tr>
<tr><td>4494</td><td></td><td>9203775</td><td>×</td><td>unknown</td></tr>
<tr><td>25586</td><td></td><td>52401552</td><td>×</td><td>unknown</td></tr>
<tr><td>21214</td><td></td><td>43446532</td><td>×</td><td>unknown</td></tr>
<tr><td>27793</td><td></td><td>56920439</td><td>×</td><td>unknown</td></tr>
<tr><td>26992</td><td></td><td>55281185</td><td>×</td><td>unknown</td></tr>
<tr><td>44308</td><td></td><td>90744648</td><td>×</td><td>unknown</td></tr>
</tbody>
</table>

## Conclusion
<table class="table is-striped is-bordered">
<tbody>
<tr class="has-text-centered has-text-primary-dark"><td>SHA256</td><td>DexDen</td><td>Conf. in APK</td><td>TippyTime</td><td>TippyPad</td><td>Cert not before</td><td>VT submission</td><td>Suspected build date</td></tr>
<tr><td>c2ce202e6e08c41e8f7a0b15e7d07817<br>04e17f8ed52d1b2ad7212ac29926436e</td>
<td class="has-text-centered has-text-danger">×</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-danger">×</td><td class="has-text-centered has-text-danger">×</td><td>2016/10/10</td><td>2017/07/27</td><td>approx. 2017/06/01</td></tr>
<tr><td>2f881b98088bbe91dc8fd003eed17f41<br>a35182a27663e6e103b2b6673b592350</td>
<td class="has-text-centered has-text-danger">×</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-danger">×</td><td>2014/10/21</td><td>2019/10/12</td><td></td></tr>
<tr><td>269227c4c4770e109e53c6cf87bd9bde<br>367843c4806f5975c5aa317f318e28a9</td>
<td class="has-text-centered has-text-danger">×</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-danger">×</td><td>2018/06/20</td><td>2019/03/24</td><td>&gt; 2017/12/07</td></tr>
<tr><td>1221bb41b315b5d6dc336a931eb4fb6f<br>eca7fe80e8dc42647c16686629767ec8</td>
<td class="has-text-centered has-text-danger">×</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-success">✔</td><td>2017/05/29</td><td>2017/09/13</td><td>&gt; 2017/05/29</td></tr>
<tr><td>269227c4c4770e109e53c6cf87bd9bde<br>367843c4806f5975c5aa317f318e28a9</td>
<td class="has-text-centered has-text-danger">×</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-danger">×</td><td>2018/06/20</td><td>2019/03/24</td><td>&gt; 2018/06/20</td></tr>
<tr><td>a504ba88c39c325589079afd7822cc4b<br>431182c8ec0304f21316e964b6e9eb7f</td>
<td class="has-text-centered has-text-danger">×</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-danger">×</td><td>2017/11/16</td><td>2018/07/31</td><td>&gt; 2017/11/16</td></tr>
<tr class="has-background-success-light"><td>854774a198db490a1ae9f06d5da5fe6a<br>1f683bf3d7186e56776516f982d41ad3</td>
<td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-danger">×</td><td class="has-text-centered has-text-success">✔</td><td class="has-text-centered has-text-success">✔</td><td>2017/05/27</td><td>2019/11/27</td><td>&gt; 2017/05/27</td></tr>
</tbody>
</table>

Our analysis based on 3 different parameters: configuration location, string obfuscation and local socket address generation tends to demonstrate that the sample we have analyzed is (as far as we know) the only known FinSpy for Android sample storing its configuration directly into the DEX file (DexDen). Reports [FinSpy Dokumentation yaraby Thorsten Schröder & Linus Neumann - CCC (Jan. 2020)](https://github.com/Linuzifer/FinSpy-Dokumentation), [AccessNow: FinFisher changes tactics to hooks critics (May 2018)](https://www.accessnow.org/cms/assets/uploads/2018/05/FinFisher-changes-tactics-to-hook-critics-AN.pdf) and [Hacking FinSpy by Sophos (2015)](https://www.troopers.de/media/filer_public/45/b6/45b61ede-cffa-484d-8064-067c76b200cf/attilamarosihacking_finspy_v016.pdf) explain how the FinSpy configuration is stored in the APK file metadata. A retro-hunt on VT has found 0 samples (our sample excluded) storing the configuration the DEX. Changing the configuration location is a strong structural change indicating a suspected new version of FinSpy for Android.

A trend emerges when we focus on how the local socket address is generated and how strings are obfuscated. Old samples do not use a “magic” timestamp (TippyTime) in the generation algorithm nor pad-obfuscated strings (TippyPad). By analyzing briefly samples shared by CCC, we observed that since 2017, FinSpy seems to use TippyTime. However, only one sample use TippyPad string obfuscation. 

Regarding unknown or undocumented TLV types, we have no clue indicating they are new or not since we have not analyzed other samples in deep and no unknown TLV types have ever been reported.


# Sample behavioral analysis
The sample we analyze is heavily obfuscated:
* strings are encoded at the class level;
* Java methods are obfuscated (shortened);
* control flow graph is broken by the heavy use of threads and IPC;
* dummy calls are inserted between almost all the “useful” ones.

To analyze the sample, we firstly do a fast behavioral recon with Aether by extracting control flow graphs in which:
* sinks are Java methods of interest;
* sources are detected entry-points (i.e. services, threads, activities, …).

Secondly we extract TLV types involved in the different control flow graphs and then correlate the meaning of TLV with the meaning of actions done on the OS.

## Configuration parsing

{{< fig src="img/locate_dex.png" caption="CFG locating the DEX file" >}}

As we have seen before FinSpy stores its configuration into the DEX file. Thus, the first step for it is to locate the DEX file. On Android, the Java method `android.content.Context.getPackageCodePath()` returns the location of the APK which contains the original DEX (not the optimized one).
Once located, the DEX file is copied at a randomly generated path into the cache directory. Once copied, the DEX loaded (or self-loaded since it is loaded by itself) using the Java method `dalvik.system.DexClassLoader.loadClass()`.

{{< fig src="img/dex_loader.png" caption="CFG loading the DEX file" >}}

Finally, FinSpy parses its configuration stored into the loaded DEX using a large switch-case statement. 

{{< fig src="img/read_config.png" caption="CFG parsing the configuration" >}}

The configuration stored into the current sample looks like:

* `TlvTypeMobileTargetID` = "WIFI"
* `TlvTypeMobileTargetHeartbeatInterval` = 120
* `TlvTypeMobileTargetPositioning` = b'\x82\x87\x86\x81\x83'
* `TlvTypeConfigTargetProxy` = "[redacted]"
* `TlvTypeConfigTargetProxy` = "[redacted]"
* `TlvTypeConfigTargetPort` = [redacted]
* `TlvTypeConfigSMSPhoneNumber` = "[redacted]"
* `TlvTypeMobileTrojanID` = "WIFI"
* `TlvTypeMobileTrojanUID` = b'\xfc\x14\xb0\r'
* `TlvTypeUserID` = 1000
* `TlvTypeTrojanMaxInfections` = 9
* `TlvTypeConfigMobileAutoRemovalDateTime` = Thu Jan  1 01:00:00 1970
* `TlvTypeConfigAutoRemovalIfNoProxy` = 168
* `TlvTypeMobileTargetHeartbeatEvents` = 173
* `TlvTypeMobileTargetHeartbeatRestrictions` = b'\xd0\x00'
* `TlvTypeMobileTrackingDistance` = 1000
* `TlvTypeMobileTrackingTimeInterval` = 300
* `TlvTypeInstalledModules` = 
  * Logging: Off 
  * Spy Call: Off 
  * Call Interception: Off
  * SMS: On
  * Address Book: On
  * Tracking: On 
  * Phone Logs: On

Note: Trojan UID is the AES sub-key used to encrypt/decrypt payloads exchange with the C2.

## Emergency reconfiguration
FinSpy can be reconfigured by SMS, the Java method `org.xmlpush.v3.q.c.a()` is dedicated to that. FinSpy uses a lot of threads, probably not for performance purposes but to circumvent automatic reverse engineering of CFG. The following CFG shows the break in the CFG.

{{< fig src="img/read_sms_configuration.png" caption="FinSpy reconfiguration" >}}

When an SMS corresponding to `TlvTypeMobileTargetEmergencyConfig` is received, FinSpy reconfigures itself by parsing the SMS payload.
The following attributes can be reconfigured:

* `TlvTypeConfigTargetPort`: port for C2 proxy
* `TlvTypeConfigSMSPhoneNumber`: phone number for SMS based C2 communications
* `TlvTypeMobileTrojanID`: unknown purpose
* `TlvTypeMobileTrojanUID`: AES sub-key
* `TlvTypeUserID`: unknown purpose
* `TlvTypeTrojanMaxInfections`: unknown purpose
* `TlvTypeConfigMobileAutoRemovalDateTime`: implant self-destruct past this date
* `TlvTypeConfigAutoRemovalIfNoProxy`: implant self-destruct if C2 proxy is unavailable
* `TlvTypeMobileTargetHeartbeatRestrictions`: conditions to avoid callbacks
* `TlvTypeMobileTargetHeartbeatEvents`: events to trigger callbacks to the C2
* `TlvTypeMobileTargetLocationChangedRange`: trigger updates based on location changes
* `TlvTypeInstalledModules`: list of implant features and their configuration (SMS log, call log, etc.)
* and other unknown parameters

## Privilege escalation

{{< fig src="img/runtime_exec.png" caption="Runtime command execution" >}}

FinSpy needs super user privileges to do things like access data of other applications. When started, the implant checks if `su` is available and then check if the user id is `0`. We found no evidence of vulnerability exploitation (DirtyCow or SELinux abuse) like the ones mentioned in other publicly available reports. We did not find ELF hidden into the APK, DEX or into natives libraries packaged in the APK.

Either we have missed something or this sample is tailored to be implanted after exploitation.

## Communication with C2

{{< fig src="img/send_http.png" caption="HTTP based exfiltration" >}}

{{< fig src="img/send_sms.png" caption="SMS based exfiltration" >}}

The implant can use both SMS and HTTP requests to send collected data to the command and control server. Both SMS and HTTP communications use the same marshaling schema based on TLV types describing data. Payload are encrypted before being sent. The encryption mechanism is the same as the one described in [AccessNow: FinFisher changes tactics to hooks critics](https://www.accessnow.org/cms/assets/uploads/2018/05/FinFisher-changes-tactics-to-hook-critics-AN.pdf).

## Self-destruction capability

{{< fig src="img/self_desctruct_and_priv.png" caption="FinSpy self-destruct script generation" >}}

Since FinSpy has the ability to remove itself, it generates a shell script `/system/etc/xrebuild.sh` listed below.
```bash
#!/system/bin/sh
mount -o rw,remount /system
am force-stop <package name>
dd if=/dev/zero of=<apk path> bs=1024 count=8192
find <path> | while read line; do dd if=/dev/zero of=$line bs=1024 count=8192; done
```

Then it makes the script executable and reboots the device. 

The script writes zeros over the APK file and does the same for all files located into the application data directory. FinSpy can be configured to remove itself at a given date and time, when the C2 is not reachable for a given amount of time or when the implant receive a specific command. By filling all files with zeros, FinSpy prevents forensic investigation. The script generation takes in account the fact that the implant can be a system application or a regular application.

## Data collection

{{< fig src="img/observe_content_changes.png" caption="FinSpy content changes tracking" >}}

Java class `org.xmlpush.v3.Services` registers the following content observers on:

* changes on phone contact list 
* changes on SIM contact list
* changes on SMS log 
* changes on calendar

Java class `org.xmlpush.v3.eventbased.ReceiverService` listens to the following events:

* new outgoing phone call
* new data SMS received 
* SIM card has been changed

Numerous threads are started to periodically check device location and messenger applications files. Every time a change occurs on observed data or an event occurs, FinSpy collects data related to that change/event and sends it to the C2 either over HTTP or SMS.

### Data collected and sent by default
The FinSpy code shows that all payloads sent to C2s contain at least:

* trojan UID
* phone number
* timezone
* current date and time
* mobile operator name
* country code based on mobile network
* location area code
* mobile cell ID

### Messenger applications data exfiltration
FinSpy is designed to exfiltrate contacts, messages, groups, location and files of the following applications:

* `com.viber.voip`
* `jp.naver.line.android`
* `com.skype.raider`
* `com.facebook.orca`
* `com.futurebits.instamessage.free`
* `jp.naver.line.android`
* `com.viber.voip`
* `com.skype.raider`
* `com.futurebits.instamessage.free`
* `com.bbm`
* `ch.threema.app`
* `org.telegram.messenger`

FinSpy looks at the content of each application data directory (i.e. `/data/data/com.futurebits.instamessage.free/`). This capability has already been documented in many public reports.

### Call log exfiltration
FinSpy exfiltrates the following information each time a call is placed:

* caller’s phone number
* callee’s phone number
* caller’s name
* callee’s name
* call duration is seconds

### SMS log exfiltration
FinSpy exfiltrates the following information each time a SMS received:

* date and time
* sender’s phone number
* recipient’s phone number
* SMS content

### Calendar events exfiltration
FinSpy exfiltrates the following information each time a new event is added/edited:

* attendees’ names
* attendees’ emails
* event title
* event description
* event location
* event start and end date

### Address book exfiltration
FinSpy exfiltrates the following information each time a modification is done on the address book:

* work phone number
* mobile phone number
* home phone number
* all other available phone numbers
* display name
* location
* email addresses
* postal addresses

FinSpy collects contacts stored in the phone memory and in the SIM card.

### SIM information exfiltration

{{< fig src="img/sim_phone_info.png" caption="SIM information retrieval" >}}

Each time the SIM card is changed, FinSpy sends the following data to the C2:

* phone number
* SIM serial number
* IMEI
* IMSI
* network operator name

### Location tracking

{{< fig src="img/gps_location.png" caption="GPS based location tracking" >}}


{{< fig src="img/net_location.png" caption="Network based location tracking" >}}

FinSpy periodically collects and sends the device location. It collects both GPS based location and network based location by using cells.