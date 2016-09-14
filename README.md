# WAS
**WAS - Wait A Sec**: Automatic USB drive malware scanning tool for the security-minded person.

Author: **Fabio Baroni**
[http://www.pentest.guru/](http://www.pentest.guru/) [@Fabiothebest89](https://twitter.com/fabiothebest89)

How many times have you plugged in a USB drive and double clicked on a file without scanning for malware?
I guess, MANY.

**Wait A Sec!**

Even if you are a security guy, you'll often be in a hurry or absent minded and you trust your USB drive (and so does your computer).
What can possibly go wrong? Getting pwned is only a click away. You may have an antivirus with realtime protection, but if it doesn't have the signatures for a new virus it's very possible that it will be unnoticed and even heuristic scan may fail in detecting a new virus. Viruses are getting increasingly sophisticated.

Luckily there are services like **Virus Total** that allow you to scan a file with multiple antiviruses in order to increase the detection rate.

You may head over to Virus Total website and upload all the files manually one by one or you may use one of the scripts already available that allow you to check a file using Virus Total API, but this tool is unique in his genre because:

* it allows to detect automatically the insertion of a new USB key
* scan recursively all the files contained in the USB drive
* hash the files and check them against the database of files already scanned by Virus Total
* get an audio message every time a new virus is detected
* automatically visualize a report in CSV format at the end of the scan

Note: although the core functions work in a crossplatform fashion, the automatic detection of a new USB key works only on Windows at the moment.

## USAGE
```
python was.py
```
As simple as that. This tool has been designed with the **run and forget** concept in mind.

Just keep it running. You don't need to execute it every time you want to use it.

## CONFIG
This tool uses a configuration file (**was-config.ini**) that allows you to specify some settings:

* **api-key**: Virus Total api key that is necessary for the program to work
* **lang**: language to be used for the notifications (e.g. EN, IT)
* **sound**: enables/disables audio notifications
* **lock**: enables/disables file-locking for files that aren't scanned yet or prove to be infected. (function not yet implemented)


## DEPENDENCIES

This tool requires Python 3.x to run and requires the following modules not included in the standard library:
* **win32api**, **win32con** and **win32gui** included in the [**PyWin32**](https://sourceforge.net/projects/pywin32/files/pywin32/) package
* [**pyglet**](https://pypi.python.org/pypi/pyglet)
* [**AVbin** library](http://avbin.github.io/) necessary for playing mp3 files with **pyglet**

---

## TODO
- add support for more languages
- implement file-locking function
- implement file upload function for scanning files not already scanned by Virus Total
- create Windows binary for ease of use by Windows folks
- add Linux support

