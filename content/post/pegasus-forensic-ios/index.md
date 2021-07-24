---
title: "How to backup and analyse iOS devices against Pegasus IOCs using Docker and MVT"
date: 2021-07-23
tags: [Mobile, Forensic, Pegasus, iOS]
draft: false
slug: "pegasus-ios-forensic"
---

This guide gives you a step-by-step procedure to conduct forensic analysis of an iOS device using [Mobile Verification Toolkit (MVT)](https://github.com/mvt-project/mvt) created by Amnesty Tech team. 

This guide is written and maintained by [Esther Onfroy](https://twitter.com/U039b) & [Abir Ghattas](https://twitter.com/abirghattas). 

## Why?
People are struggling to analyze iOS devices due to the complexity of the procedure on Linux. We have decided to use Docker because latest versions of iOS require the use of a version of `libimobiledevice` which is not available on Linux yet. We use `libimobiledevice` to backup the iOS device instead of using iTunes.

This guide has been successfully tested on Ubuntu 20.04 with:

* iOS 13.5.1
* iOS 14.5
* iOS 14.7

## Requirements
* A Debian-based operating system
* A root access on your computer
* [Docker](https://docs.docker.com/engine/install/) already installed 
* **Knowledge in Linux command-line**



Follow each step in the same terminal session.

## Prepare your computer

##### 1. Create a directory for your investigations
```bash
mkdir Pegasus_investigations
cd Pegasus_investigations
```

##### 2. Prepare directory structure
```bash
mkdir ioc backup decrypted checked
```

##### 3. Retrieve IOC provided by Amnesty International
```bash
wget https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2 -O ioc/pegasus.stix2
```
If you want to learn more about the IOC, check [the Amnesty Tech repository](https://github.com/AmnestyTech/investigations/tree/master/2021-07-18_nso).

##### 4. Retrieve the Dockerfile
```bash
wget https://raw.githubusercontent.com/mvt-project/mvt/main/Dockerfile -O Dockerfile
```

##### 5. Build the Docker image
Depending on you setup, we would have to be root from this step to the end of the investigation.
```bash
docker build -t mvt .
```

## Prepare the iOS device to be analyzed
##### 6. Plug your iOS device to your computer
Do not unplug it until the end of the backup procedure and be sure to keep the device unlocked

##### 7. Stop the USB mixer
```bash
systemctl stop usbmuxd
```
This command could take a bit of time, just wait.

##### 8. Start the Docker container 
```bash
docker run -it --privileged --rm -v /dev/bus/usb:/dev/bus/usb --net=host \
  -v $PWD/ioc:/home/cases/ioc \
  -v $PWD/decrypted:/home/cases/decrypted \
  -v $PWD/checked:/home/cases/checked \
  -v $PWD/backup:/home/cases/backup \
  mvt
```
Now any command you run will be executed inside the container.

##### 9. Start the USB mixer
```bash
usbmuxd
```
The iOS device may be asking you if you trust the connected computer, trust it.

##### 10. Check if the iOS is recognized
```bash
ideviceinfo
```

## Backup the iOS device
##### 11. Turn backup encryption on
```bash
idevicebackup2 backup encryption on -i
```

##### 12. Backup the iOS device
```bash
idevicebackup2 backup --full backup/
```
Once done, you can unplug the iOS device. Run `ls -l backup` to get the name of the backup.

## Analyze the backup
##### 13. Decrypt the backup
```bash
mvt-ios decrypt-backup -p <backup password> -d decrypted backup/<backup name>
```
For more details and options, check [the MVT documentation](https://mvt.readthedocs.io/en/latest/ios/backup/check.html) and [the note regarding the backup password](https://mvt.readthedocs.io/en/latest/ios/backup/libimobiledevice.html).
If you have backed up this phone using iTunes, the **backup password** is the same as the one you provided in iTunes.

##### 14. Analyze the backup
```bash
mvt-ios check-backup -o checked --iocs ioc/pegasus.stix2 decrypted
```

##### 15. Check the results
```bash
ls -l checked
```
The folder `checked` contains [several JSON files](https://mvt.readthedocs.io/en/latest/ios/records.html).
**Any IOC matches are stored in JSON files suffixed by `_detected`.**
 
##### 16. Exit the container
```bash
exit
```

##### 17. Save the outputs
If you want to keep the files generated during the forensic procedure, backup the following folders:

* `backup` containing the iOS backup
* `decrypted` containing the decrypted backup
* `checked` containing the results of MVT analysis


















